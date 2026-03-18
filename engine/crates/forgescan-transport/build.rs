//! Build script to compile protobuf definitions

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../proto")
        .canonicalize()
        .unwrap_or_else(|_| {
            // Fallback for when canonicalize fails
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../proto")
        });

    let protos: Vec<std::path::PathBuf> = vec![
        proto_dir.join("common.proto"),
        proto_dir.join("results.proto"),
        proto_dir.join("scan_service.proto"),
        proto_dir.join("agent_service.proto"),
    ];

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile(&protos, &[&proto_dir])?;

    Ok(())
}
