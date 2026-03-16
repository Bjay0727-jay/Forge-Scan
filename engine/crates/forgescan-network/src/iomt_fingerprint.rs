//! Medical Device and IoMT Fingerprinting
//!
//! Identifies medical devices, IoT equipment, and healthcare-specific protocols
//! based on port patterns, service banners, and protocol characteristics.
//!
//! Supports:
//! - HL7v2/FHIR interface engines
//! - DICOM servers and PACS systems
//! - BACnet building automation
//! - Modbus industrial control
//! - MQTT IoT messaging
//! - Medical device manufacturer fingerprinting

use forgescan_core::{DeviceClass, MedicalProtocol};

use crate::banner::BannerResult;
use crate::service_detect::ServiceInfo;

/// Well-known ports for medical/IoT protocols
pub mod ports {
    /// DICOM (Digital Imaging and Communications in Medicine)
    pub const DICOM: u16 = 104;
    /// DICOM TLS
    pub const DICOM_TLS: u16 = 2762;
    /// HL7 MLLP (Minimal Lower Layer Protocol)
    pub const HL7_MLLP: u16 = 2575;
    /// BACnet/IP
    pub const BACNET: u16 = 47808;
    /// Modbus TCP
    pub const MODBUS: u16 = 502;
    /// MQTT (unencrypted)
    pub const MQTT: u16 = 1883;
    /// MQTT over TLS
    pub const MQTT_TLS: u16 = 8883;
    /// HL7 FHIR (typically HTTPS)
    pub const FHIR_DEFAULT: u16 = 443;
    /// Common HL7 interface engine admin ports
    pub const HL7_ADMIN_PORTS: &[u16] = &[8080, 8443, 9090, 9443];
}

/// Result of IoMT device fingerprinting
#[derive(Debug, Clone)]
pub struct IoMTFingerprint {
    /// Detected device class
    pub device_class: DeviceClass,
    /// Detected manufacturer
    pub manufacturer: Option<String>,
    /// Device model
    pub model: Option<String>,
    /// Firmware version
    pub firmware_version: Option<String>,
    /// Medical protocols detected
    pub protocols: Vec<MedicalProtocol>,
    /// Classification confidence (0-100)
    pub confidence: u8,
    /// Evidence strings supporting the classification
    pub evidence: Vec<String>,
}

/// Known medical device manufacturer banner patterns
struct ManufacturerPattern {
    keywords: &'static [&'static str],
    manufacturer: &'static str,
    device_class: DeviceClass,
    model_hint: Option<&'static str>,
}

/// Medical device fingerprinter
pub struct IoMTFingerprinter {
    manufacturer_patterns: Vec<ManufacturerPattern>,
}

impl Default for IoMTFingerprinter {
    fn default() -> Self {
        Self::new()
    }
}

impl IoMTFingerprinter {
    pub fn new() -> Self {
        Self {
            manufacturer_patterns: Self::default_manufacturer_patterns(),
        }
    }

    /// Attempt to classify a host as a medical/IoT device based on port and banner data
    pub fn fingerprint(
        &self,
        open_ports: &[u16],
        banners: &[BannerResult],
        services: &[ServiceInfo],
    ) -> Option<IoMTFingerprint> {
        let mut evidence = Vec::new();
        let mut protocols = Vec::new();
        let mut device_class = None;
        let mut manufacturer = None;
        let mut model = None;
        let mut firmware_version = None;
        let mut confidence: u8 = 0;

        // Phase 1: Protocol detection from ports
        for &port in open_ports {
            if let Some(proto) = self.detect_protocol_from_port(port) {
                protocols.push(proto);
                evidence.push(format!("Port {} indicates {:?} protocol", port, proto));
                confidence = confidence.max(40);
            }
        }

        // Phase 2: Banner-based manufacturer detection
        for banner in banners {
            if let Some(mfr_match) = self.detect_manufacturer_from_banner(&banner.text) {
                manufacturer = Some(mfr_match.manufacturer.to_string());
                if device_class.is_none()
                    || mfr_match.confidence > confidence
                {
                    device_class = Some(mfr_match.device_class);
                }
                if let Some(m) = mfr_match.model {
                    model = Some(m);
                }
                if let Some(fw) = mfr_match.firmware {
                    firmware_version = Some(fw);
                }
                evidence.push(format!(
                    "Banner matches {} device pattern",
                    mfr_match.manufacturer
                ));
                confidence = confidence.max(mfr_match.confidence);
            }
        }

        // Phase 3: Service-based detection
        for service in services {
            if let Some(class) = self.detect_device_from_service(service) {
                if device_class.is_none() {
                    device_class = Some(class);
                }
                evidence.push(format!(
                    "Service '{}' indicates {:?} device",
                    service.name, class
                ));
                confidence = confidence.max(50);
            }
        }

        // Phase 4: Multi-port correlation (higher confidence)
        if let Some(class) = self.correlate_ports(open_ports) {
            if device_class.is_none() || confidence < 60 {
                device_class = Some(class);
                evidence.push("Multi-port correlation indicates medical device".to_string());
                confidence = confidence.max(60);
            }
        }

        // Only return a fingerprint if we detected something
        let device_class = device_class?;

        if protocols.is_empty() && confidence < 30 {
            return None;
        }

        Some(IoMTFingerprint {
            device_class,
            manufacturer,
            model,
            firmware_version,
            protocols,
            confidence,
            evidence,
        })
    }

    /// Detect medical protocol from port number
    fn detect_protocol_from_port(&self, port: u16) -> Option<MedicalProtocol> {
        match port {
            ports::DICOM | ports::DICOM_TLS => Some(MedicalProtocol::DICOM),
            ports::HL7_MLLP => Some(MedicalProtocol::HL7v2),
            ports::BACNET => Some(MedicalProtocol::BACnet),
            ports::MODBUS => Some(MedicalProtocol::Modbus),
            ports::MQTT | ports::MQTT_TLS => Some(MedicalProtocol::MQTT),
            _ => None,
        }
    }

    /// Detect manufacturer from banner text
    fn detect_manufacturer_from_banner(&self, banner: &str) -> Option<ManufacturerMatch> {
        let banner_lower = banner.to_lowercase();

        for pattern in &self.manufacturer_patterns {
            if pattern
                .keywords
                .iter()
                .all(|kw| banner_lower.contains(kw))
            {
                return Some(ManufacturerMatch {
                    manufacturer: pattern.manufacturer,
                    device_class: pattern.device_class,
                    model: pattern.model_hint.map(String::from),
                    firmware: Self::extract_version(&banner_lower),
                    confidence: 70,
                });
            }
        }

        // Generic medical device detection from common keywords
        if banner_lower.contains("dicom") || banner_lower.contains("pacs") {
            return Some(ManufacturerMatch {
                manufacturer: "Unknown",
                device_class: DeviceClass::DICOMServer,
                model: None,
                firmware: None,
                confidence: 60,
            });
        }
        if banner_lower.contains("hl7") || banner_lower.contains("mllp") {
            return Some(ManufacturerMatch {
                manufacturer: "Unknown",
                device_class: DeviceClass::HL7Router,
                model: None,
                firmware: None,
                confidence: 60,
            });
        }

        None
    }

    /// Detect device class from service information
    fn detect_device_from_service(&self, service: &ServiceInfo) -> Option<DeviceClass> {
        let name_lower = service.name.to_lowercase();

        if name_lower.contains("dicom") {
            return Some(DeviceClass::DICOMServer);
        }
        if name_lower.contains("hl7") {
            return Some(DeviceClass::HL7Router);
        }
        if name_lower.contains("bacnet") {
            return Some(DeviceClass::BuildingAutomation);
        }
        if name_lower.contains("modbus") {
            return Some(DeviceClass::IndustrialControl);
        }
        if name_lower.contains("mqtt") {
            return Some(DeviceClass::GenericIoT);
        }

        // Check product field for medical device indicators
        if let Some(ref product) = service.product {
            let product_lower = product.to_lowercase();
            if product_lower.contains("mirth") || product_lower.contains("ensemble") {
                return Some(DeviceClass::HL7Router);
            }
            if product_lower.contains("orthanc")
                || product_lower.contains("dcm4chee")
                || product_lower.contains("conquest")
            {
                return Some(DeviceClass::DICOMServer);
            }
        }

        None
    }

    /// Correlate multiple open ports to identify device class
    fn correlate_ports(&self, ports: &[u16]) -> Option<DeviceClass> {
        let has_dicom = ports.contains(&ports::DICOM);
        let has_hl7 = ports.contains(&ports::HL7_MLLP);
        let has_bacnet = ports.contains(&ports::BACNET);
        let has_modbus = ports.contains(&ports::MODBUS);
        let has_http = ports.contains(&80) || ports.contains(&443) || ports.contains(&8080);

        // DICOM + HTTP = likely PACS/imaging workstation
        if has_dicom && has_http {
            return Some(DeviceClass::MedicalImaging);
        }

        // DICOM alone = DICOM server
        if has_dicom {
            return Some(DeviceClass::DICOMServer);
        }

        // HL7 + HTTP = HL7 interface engine
        if has_hl7 && has_http {
            return Some(DeviceClass::HL7Router);
        }

        // HL7 alone
        if has_hl7 {
            return Some(DeviceClass::HL7Router);
        }

        // BACnet = building automation
        if has_bacnet {
            return Some(DeviceClass::BuildingAutomation);
        }

        // Modbus = industrial control
        if has_modbus {
            return Some(DeviceClass::IndustrialControl);
        }

        None
    }

    /// Extract version string from banner
    fn extract_version(banner: &str) -> Option<String> {
        // Look for common version patterns: x.y.z, vX.Y, Version X.Y
        let version_patterns = [
            r"(\d+\.\d+\.\d+[\.\-\w]*)",
            r"v(\d+\.\d+)",
            r"version\s+(\d+[\.\d]+)",
        ];

        for pattern in &version_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if let Some(caps) = re.captures(banner) {
                    if let Some(m) = caps.get(1) {
                        return Some(m.as_str().to_string());
                    }
                }
            }
        }

        None
    }

    /// Build default manufacturer detection patterns
    fn default_manufacturer_patterns() -> Vec<ManufacturerPattern> {
        vec![
            // Medical Imaging
            ManufacturerPattern {
                keywords: &["philips", "intellispace"],
                manufacturer: "Philips",
                device_class: DeviceClass::MedicalImaging,
                model_hint: Some("IntelliSpace PACS"),
            },
            ManufacturerPattern {
                keywords: &["ge", "centricity"],
                manufacturer: "GE Healthcare",
                device_class: DeviceClass::MedicalImaging,
                model_hint: Some("Centricity PACS"),
            },
            ManufacturerPattern {
                keywords: &["siemens", "syngo"],
                manufacturer: "Siemens Healthineers",
                device_class: DeviceClass::MedicalImaging,
                model_hint: Some("syngo.plaza"),
            },
            ManufacturerPattern {
                keywords: &["agfa", "impax"],
                manufacturer: "Agfa HealthCare",
                device_class: DeviceClass::MedicalImaging,
                model_hint: Some("IMPAX"),
            },
            // Patient Monitors
            ManufacturerPattern {
                keywords: &["philips", "intellivue"],
                manufacturer: "Philips",
                device_class: DeviceClass::PatientMonitor,
                model_hint: Some("IntelliVue"),
            },
            ManufacturerPattern {
                keywords: &["ge", "carescape"],
                manufacturer: "GE Healthcare",
                device_class: DeviceClass::PatientMonitor,
                model_hint: Some("CARESCAPE"),
            },
            ManufacturerPattern {
                keywords: &["mindray"],
                manufacturer: "Mindray",
                device_class: DeviceClass::PatientMonitor,
                model_hint: None,
            },
            ManufacturerPattern {
                keywords: &["spacelabs"],
                manufacturer: "Spacelabs Healthcare",
                device_class: DeviceClass::PatientMonitor,
                model_hint: None,
            },
            // Infusion Pumps
            ManufacturerPattern {
                keywords: &["alaris"],
                manufacturer: "BD (Becton Dickinson)",
                device_class: DeviceClass::InfusionPump,
                model_hint: Some("Alaris"),
            },
            ManufacturerPattern {
                keywords: &["baxter", "infusion"],
                manufacturer: "Baxter",
                device_class: DeviceClass::InfusionPump,
                model_hint: None,
            },
            ManufacturerPattern {
                keywords: &["b. braun", "infusomat"],
                manufacturer: "B. Braun",
                device_class: DeviceClass::InfusionPump,
                model_hint: Some("Infusomat"),
            },
            // Ventilators
            ManufacturerPattern {
                keywords: &["draeger"],
                manufacturer: "Dräger",
                device_class: DeviceClass::Ventilator,
                model_hint: None,
            },
            ManufacturerPattern {
                keywords: &["hamilton", "ventilator"],
                manufacturer: "Hamilton Medical",
                device_class: DeviceClass::Ventilator,
                model_hint: None,
            },
            ManufacturerPattern {
                keywords: &["medtronic", "puritan"],
                manufacturer: "Medtronic",
                device_class: DeviceClass::Ventilator,
                model_hint: Some("Puritan Bennett"),
            },
            // HL7 Interface Engines
            ManufacturerPattern {
                keywords: &["mirth", "connect"],
                manufacturer: "NextGen Healthcare",
                device_class: DeviceClass::HL7Router,
                model_hint: Some("Mirth Connect"),
            },
            ManufacturerPattern {
                keywords: &["intersystems", "ensemble"],
                manufacturer: "InterSystems",
                device_class: DeviceClass::HL7Router,
                model_hint: Some("HealthShare/Ensemble"),
            },
            ManufacturerPattern {
                keywords: &["rhapsody"],
                manufacturer: "Rhapsody",
                device_class: DeviceClass::HL7Router,
                model_hint: Some("Rhapsody Integration Engine"),
            },
            // DICOM Servers
            ManufacturerPattern {
                keywords: &["orthanc"],
                manufacturer: "Orthanc",
                device_class: DeviceClass::DICOMServer,
                model_hint: Some("Orthanc DICOM Server"),
            },
            ManufacturerPattern {
                keywords: &["dcm4chee"],
                manufacturer: "dcm4che.org",
                device_class: DeviceClass::DICOMServer,
                model_hint: Some("dcm4chee"),
            },
        ]
    }
}

/// Internal result from manufacturer detection
struct ManufacturerMatch {
    manufacturer: &'static str,
    device_class: DeviceClass,
    model: Option<String>,
    firmware: Option<String>,
    confidence: u8,
}

/// Determine if a set of open ports suggests a medical device network segment
pub fn is_medical_network_segment(hosts_ports: &[(std::net::IpAddr, Vec<u16>)]) -> bool {
    let mut medical_port_count = 0;
    for (_, ports) in hosts_ports {
        for port in ports {
            if matches!(
                *port,
                ports::DICOM
                    | ports::DICOM_TLS
                    | ports::HL7_MLLP
                    | ports::BACNET
                    | ports::MODBUS
            ) {
                medical_port_count += 1;
            }
        }
    }
    // If more than 10% of hosts have medical ports, likely a clinical VLAN
    let threshold = (hosts_ports.len() / 10).max(1);
    medical_port_count >= threshold
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::banner::ProbeType;

    #[test]
    fn test_protocol_detection_from_port() {
        let fp = IoMTFingerprinter::new();
        assert_eq!(
            fp.detect_protocol_from_port(104),
            Some(MedicalProtocol::DICOM)
        );
        assert_eq!(
            fp.detect_protocol_from_port(2575),
            Some(MedicalProtocol::HL7v2)
        );
        assert_eq!(
            fp.detect_protocol_from_port(47808),
            Some(MedicalProtocol::BACnet)
        );
        assert_eq!(
            fp.detect_protocol_from_port(502),
            Some(MedicalProtocol::Modbus)
        );
        assert_eq!(
            fp.detect_protocol_from_port(1883),
            Some(MedicalProtocol::MQTT)
        );
        assert_eq!(fp.detect_protocol_from_port(22), None);
    }

    #[test]
    fn test_dicom_banner_detection() {
        let fp = IoMTFingerprinter::new();
        let banner = "1.2.840.10008.1.2 DICOM Transfer Syntax";
        let result = fp.detect_manufacturer_from_banner(banner);
        assert!(result.is_some());
        assert_eq!(result.unwrap().device_class, DeviceClass::DICOMServer);
    }

    #[test]
    fn test_manufacturer_detection() {
        let fp = IoMTFingerprinter::new();
        let banner = "Philips IntelliVue Patient Monitor MX800 v3.2.1";
        let result = fp.detect_manufacturer_from_banner(banner);
        assert!(result.is_some());
        let m = result.unwrap();
        assert_eq!(m.manufacturer, "Philips");
        assert_eq!(m.device_class, DeviceClass::PatientMonitor);
    }

    #[test]
    fn test_full_fingerprint() {
        let fp = IoMTFingerprinter::new();

        let open_ports = vec![104, 80, 443];
        let banners = vec![BannerResult {
            raw: b"DICOM Server Orthanc 1.12.1".to_vec(),
            text: "DICOM Server Orthanc 1.12.1".to_string(),
            probe_used: ProbeType::Null,
        }];
        let services = vec![];

        let result = fp.fingerprint(&open_ports, &banners, &services);
        assert!(result.is_some());
        let r = result.unwrap();
        assert!(matches!(
            r.device_class,
            DeviceClass::DICOMServer | DeviceClass::MedicalImaging
        ));
        assert!(r.protocols.contains(&MedicalProtocol::DICOM));
    }

    #[test]
    fn test_port_correlation() {
        let fp = IoMTFingerprinter::new();

        assert_eq!(
            fp.correlate_ports(&[104, 80]),
            Some(DeviceClass::MedicalImaging)
        );
        assert_eq!(
            fp.correlate_ports(&[2575, 8080]),
            Some(DeviceClass::HL7Router)
        );
        assert_eq!(
            fp.correlate_ports(&[47808]),
            Some(DeviceClass::BuildingAutomation)
        );
        assert_eq!(fp.correlate_ports(&[22, 80, 443]), None);
    }

    #[test]
    fn test_medical_network_segment() {
        let hosts: Vec<(std::net::IpAddr, Vec<u16>)> = vec![
            ("10.0.1.1".parse().unwrap(), vec![104, 80]),
            ("10.0.1.2".parse().unwrap(), vec![2575, 22]),
            ("10.0.1.3".parse().unwrap(), vec![80, 443]),
            ("10.0.1.4".parse().unwrap(), vec![22, 80]),
        ];
        assert!(is_medical_network_segment(&hosts));

        let non_medical: Vec<(std::net::IpAddr, Vec<u16>)> = vec![
            ("10.0.2.1".parse().unwrap(), vec![22, 80]),
            ("10.0.2.2".parse().unwrap(), vec![443, 8080]),
        ];
        assert!(!is_medical_network_segment(&non_medical));
    }
}
