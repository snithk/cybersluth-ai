#!/usr/bin/env python3

import os
import logging
from datetime import datetime
from dotenv import load_dotenv
from src.analyzers.network_analyzer import NetworkAnalyzer
from src.analyzers.log_analyzer import LogAnalyzer
from src.analyzers.artifact_analyzer import ArtifactAnalyzer
from src.models.threat_detector import ThreatDetector
from src.utils.report_generator import ReportGenerator
from src.utils.config import Config

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CyberForensicsAnalyzer:
    def __init__(self):
        load_dotenv()
        self.config = Config()
        self.network_analyzer = NetworkAnalyzer()
        self.log_analyzer = LogAnalyzer()
        self.artifact_analyzer = ArtifactAnalyzer()
        self.threat_detector = ThreatDetector()
        self.report_generator = ReportGenerator()

    def start_analysis(self):
        """Start the forensic analysis process"""
        logger.info("Starting Cyber Forensics Analysis")
        
        try:
            # Start network monitoring (run for 5 seconds in batch mode)
            network_data = self.network_analyzer.start_monitoring(duration=5)
            
            # Analyze system logs
            log_findings = self.log_analyzer.analyze_logs()
            
            # Analyze digital artifacts
            artifact_findings = self.artifact_analyzer.analyze_artifacts()
            
            # Detect threats using ML models
            threats = self.threat_detector.detect_threats(
                network_data=network_data,
                log_findings=log_findings,
                artifact_findings=artifact_findings
            )
            
            # Generate report
            report = self.report_generator.generate_report(
                threats=threats,
                network_data=network_data,
                log_findings=log_findings,
                artifact_findings=artifact_findings
            )
            
            logger.info("Analysis completed successfully")
            return report
            
        except Exception as e:
            logger.error(f"Error during analysis: {str(e)}")
            raise

    def real_time_monitoring(self):
        """Start real-time monitoring mode"""
        logger.info("Starting real-time monitoring")
        try:
            while True:
                self.network_analyzer.monitor_realtime()
                self.log_analyzer.monitor_realtime()
                self.threat_detector.analyze_realtime()
        except KeyboardInterrupt:
            logger.info("Stopping real-time monitoring")

def main():
    analyzer = CyberForensicsAnalyzer()
    
    if os.getenv("ANALYZER_MODE") == "realtime":
        analyzer.real_time_monitoring()
    else:
        report = analyzer.start_analysis()
        print(f"Analysis complete. Report saved to: {report}")

if __name__ == "__main__":
    main() 