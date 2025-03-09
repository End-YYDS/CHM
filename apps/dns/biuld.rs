fn main() {
    tonic_build::compile_protos("proto/dns.proto").unwrap();
}