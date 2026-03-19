/// capsec::tokio::fs::create() returns AsyncWriteFile, which does not implement AsyncRead.

fn main() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let root = capsec::root();
        let cap = root.fs_write();
        let mut file = capsec::tokio::fs::create("/tmp/test.txt", &cap).await.unwrap();
        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut file, &mut buf).await.unwrap();
    });
}
