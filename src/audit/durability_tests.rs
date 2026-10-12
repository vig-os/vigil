//! Storage-layer power-loss model. Open descriptors pin inodes until replay, so
//! unlink followed by creation cannot confuse a reused kernel inode number.
use std::{
    cell::RefCell,
    collections::BTreeMap,
    fs::{self, File},
    io,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

type Inode = (u64, u64);
struct Image {
    file: File,
    bytes: Vec<u8>,
}
struct Model {
    path: PathBuf,
    files: BTreeMap<Inode, Image>,
    names: BTreeMap<PathBuf, Inode>,
}
thread_local! {
    static MODEL: RefCell<Option<Model>> = const { RefCell::new(None) };
}
fn inode(file: &File) -> io::Result<Inode> {
    let meta = file.metadata()?;
    Ok((meta.dev(), meta.ino()))
}
fn contents(file: &File) -> io::Result<Vec<u8>> {
    use std::os::unix::fs::FileExt;
    let mut bytes = vec![0; file.metadata()?.len() as usize];
    file.read_exact_at(&mut bytes, 0)?;
    Ok(bytes)
}
impl Model {
    fn names(&mut self, initial: bool) -> io::Result<()> {
        let mut names = BTreeMap::new();
        for entry in fs::read_dir(&self.path)? {
            let entry = entry?;
            let file = File::open(entry.path())?;
            if !file.metadata()?.is_file() {
                continue;
            }
            let id = inode(&file)?;
            if let std::collections::btree_map::Entry::Vacant(slot) = self.files.entry(id) {
                let bytes = if initial {
                    contents(&file)?
                } else {
                    Vec::new()
                };
                slot.insert(Image { file, bytes });
            }
            names.insert(entry.file_name().into(), id);
        }
        self.names = names;
        Ok(())
    }
}
pub(super) fn start(path: &Path) {
    let mut model = Model {
        path: path.into(),
        files: BTreeMap::new(),
        names: BTreeMap::new(),
    };
    model.names(true).unwrap();
    MODEL.with(|slot| *slot.borrow_mut() = Some(model));
}
pub(super) fn stop() {
    MODEL.with(|slot| *slot.borrow_mut() = None);
}
pub(super) fn sync(file: &File) -> io::Result<()> {
    MODEL.with(|slot| {
        let mut slot = slot.borrow_mut();
        let Some(model) = slot.as_mut() else {
            return Ok(());
        };
        if file.metadata()?.is_dir() {
            return model.names(false);
        }
        let id = inode(file)?;
        // The writer may hold a write-only descriptor. Resolve the readable
        // descriptor through its current name, retaining it across later renames.
        let readable = if let Some(image) = model.files.get(&id) {
            image.file.try_clone()?
        } else {
            let mut found = None;
            for entry in fs::read_dir(&model.path)? {
                let candidate = File::open(entry?.path())?;
                if inode(&candidate)? == id {
                    found = Some(candidate);
                    break;
                }
            }
            found.ok_or_else(|| io::Error::other("model fsync on unknown inode"))?
        };
        let bytes = contents(&readable)?;
        model.files.insert(
            id,
            Image {
                file: readable,
                bytes,
            },
        );
        Ok(())
    })
}
/// Explore the complete-data outcome by making the staging data durable before
/// the injected failure. The later failing fsync cannot change this saved view.
pub(super) fn persist_staging(path: &Path) {
    let file = File::open(path.join(".audit-next.jsonl")).unwrap();
    file.sync_all().unwrap();
    sync(&file).unwrap();
    let dir = File::open(path).unwrap();
    dir.sync_all().unwrap();
    sync(&dir).unwrap();
}
pub(super) fn replay() {
    let model = MODEL.with(|slot| slot.borrow_mut().take().unwrap());
    for entry in fs::read_dir(&model.path).unwrap() {
        fs::remove_file(entry.unwrap().path()).unwrap();
    }
    let mut restored = BTreeMap::new();
    for (name, id) in &model.names {
        let path = model.path.join(name);
        if let Some(prior) = restored.get(id) {
            fs::hard_link(prior, &path).unwrap();
        } else {
            let image = &model.files[id];
            fs::write(&path, &image.bytes).unwrap();
            fs::set_permissions(&path, image.file.metadata().unwrap().permissions()).unwrap();
            restored.insert(*id, path);
        }
    }
}
