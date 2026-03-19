/// capsec::tokio::fs::open() returns AsyncReadFile, which does not implement AsyncWrite.

fn main() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let root = capsec::root();
        let cap = root.fs_read();
        let mut file = capsec::tokio::fs::open("/tmp/test.txt", &cap).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut file, b"nope").await.unwrap();
    });
}
