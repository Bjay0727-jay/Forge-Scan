//! Build script to compile protobuf definitions

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Uncomment when proto files are ready for compilation
    // tonic_build::configure()
    //     .build_server(true)
    //     .build_client(true)
    //     .compile(
    //         &[
    //             "../../../proto/common.proto",
    //             "../../../proto/results.proto",
    //             "../../../proto/scan_service.proto",
    //             "../../../proto/agent_service.proto",
    //         ],
    //         &["../../../proto"],
    //     )?;

    Ok(())
}
