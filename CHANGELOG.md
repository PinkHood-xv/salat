# Changelog

All notable changes to SALAT v2 will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2025-10-25

### Added
- Complete rewrite of SALAT as a professional CLI tool
- Multi-format log parsing support (JSON, PCAP, EVTX, Syslog)
- Advanced filtering capabilities by IP, time, protocol, and ports
- Automated threat detection modules:
  - Brute force attack detection
  - Port scan detection
- Multiple output formats (text, JSON, HTML, CSV)
- Timeline visualization for security events
- Educational mode showing manual analysis commands
- Comprehensive error handling and validation
- Sample logs for testing and demonstration
- Modular architecture with separate parsers, detectors, and formatters

### Changed
- Migrated from notebook-based tool to standalone CLI application
- Improved performance and scalability
- Enhanced user experience with Unix-style command-line interface
- Better documentation and help text

### Features
- **Parsers**: JSON, PCAP (tshark), EVTX, Syslog
- **Detectors**: Brute force, Port scan (extensible framework)
- **Formatters**: Text, JSON, HTML, CSV, Timeline
- **Filters**: IP address/CIDR, time ranges, protocols, ports
- **Educational**: `--show-commands` displays manual analysis techniques

## [1.0.0] - Previous Version

### Initial Release
- Original Jupyter notebook-based SALAT toolkit
- Basic log analysis capabilities
- Foundation for v2 development

---

## Version Numbering

- **Major version** (X.0.0): Breaking changes, major new features
- **Minor version** (0.X.0): New features, backwards compatible
- **Patch version** (0.0.X): Bug fixes, minor improvements
