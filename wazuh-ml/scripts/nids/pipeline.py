"""pipeline.py - Main detection pipeline orchestrating all layers"""

import logging, time
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Any
from .config import PCAP_DIR, FLOWS_DIR, WHITELIST_IPS
from .models import FlowDetection, DetectionResult, ThreatLevel
from .capture import PfSenseCapture, extract_flows
from .layers import SuricataSNIDS, XGBoostClassifier, AnomalyDetector, VAEDetector
from .actions import ActionHandler
from .stats import stats

logger = logging.getLogger(__name__)


class HybridNIDS:
    """3-Layer Hybrid NIDS: Suricata (L1), XGBoost (L2), VAE (L3)"""
    
    def __init__(self, xgboost_model: Optional[Path] = None, iforest_model: Optional[Path] = None,
                 pfsense_host: Optional[str] = None, pfsense_user: Optional[str] = None,
                 pfsense_key: Optional[str] = None, pfsense_interface: str = 'em1',
                 anomaly_threshold: float = -0.5, anomaly_model: str = 'vae'):
        self.layer1 = SuricataSNIDS(pfsense_host, pfsense_user, pfsense_key, pfsense_interface)
        self.layer2 = XGBoostClassifier(model_path=xgboost_model)
        self.layer3 = None
        
        if anomaly_model.lower() == 'vae':
            vae = VAEDetector()
            if getattr(vae, 'encoder', None) is not None and getattr(vae, 'decoder', None) is not None:
                self.layer3 = vae
                logger.info("Layer3: VAE anomaly detector enabled")
            else:
                logger.error("Layer3: VAE requested but failed to load models. Anomaly detection disabled.")
        
        elif anomaly_model.lower() == 'iforest':
            self.layer3 = AnomalyDetector(model_path=iforest_model, threshold=anomaly_threshold)
            logger.info("Layer3: Isolation Forest anomaly detector enabled")
        self.whitelist = WHITELIST_IPS
        if self.whitelist:
            logger.info(f"Whitelist loaded: {len(self.whitelist)} IPs")
        logger.info("Hybrid NIDS initialized")
    
    def analyze(self, pcap_file: Path, flows_df: Optional[Any] = None) -> DetectionResult:
        """Analyze traffic through all detection layers"""
        start = time.time()
        detections: List[FlowDetection] = []
        
        # Layer 1: Suricata
        for a in self.layer1.analyze(pcap_file):
            sev = a.get('severity', 3)
            lvl = ThreatLevel.CRITICAL if sev == 1 else ThreatLevel.HIGH if sev == 2 else ThreatLevel.MEDIUM
            detections.append(FlowDetection(
                flow_id=a.get('signature_id', 'unknown'), src_ip=a.get('src_ip', 'unknown'),
                dst_ip=a.get('dst_ip', 'unknown'), src_port=int(a.get('src_port', 0)),
                dst_port=int(a.get('dst_port', 0)), protocol=a.get('protocol', 'unknown'),
                attack_type=f"[{a.get('category', 'Sig')}] {a.get('message', 'Alert')}",
                confidence=0.95, layer='suricata', threat_level=lvl))
        
        # Extract flows if needed
        if flows_df is None: flows_df = extract_flows(pcap_file)
        total_flows = len(flows_df) if flows_df is not None else 0
        
        if flows_df is not None and len(flows_df) > 0:
            detections.extend(self.layer2.predict(flows_df))  # Layer 2
            if self.layer3 is not None:
                detections.extend(self.layer3.detect(flows_df))   # Layer 3
        
        # Track raw count before filtering
        raw_count = len(detections)
        
        # Filter whitelist and deduplicate
        detections = self._filter_whitelist(detections)
        filtered_count = raw_count - len(detections)
        
        return DetectionResult(timestamp=datetime.now(), total_flows=total_flows,
            detections=self._deduplicate(detections), processing_time=time.time() - start,
            filtered_count=filtered_count)
    
    def _filter_whitelist(self, detections: List[FlowDetection]) -> List[FlowDetection]:
        """Remove detections from/to whitelisted IPs"""
        if not self.whitelist:
            return detections
        filtered = [d for d in detections if d.src_ip not in self.whitelist and d.dst_ip not in self.whitelist]
        removed = len(detections) - len(filtered)
        if removed:
            logger.debug(f"Filtered {removed} detections from/to whitelisted IPs")
        return filtered
    
    def _deduplicate(self, detections: List[FlowDetection]) -> List[FlowDetection]:
        """Deduplicate detections by (src_ip, dst_ip, attack_type), keeping highest confidence and counting flows"""
        seen: Dict[str, FlowDetection] = {}
        counts: Dict[str, int] = {}
        for d in detections:
            key = f"{d.src_ip}-{d.dst_ip}-{d.attack_type}"
            counts[key] = counts.get(key, 0) + 1
            if key not in seen or d.confidence > seen[key].confidence:
                seen[key] = d
        # Update flow_count for each deduplicated detection
        result = []
        for key, det in seen.items():
            det.flow_count = counts[key]
            result.append(det)
        return result


class DetectionPipeline:
    """Real-time detection pipeline with continuous monitoring"""
    
    def __init__(self, pfsense_host: str, pfsense_user: str, pfsense_key: Optional[str] = None,
                 pfsense_interface: Optional[str] = None, capture_duration: int = 15,
                 action_config: Optional[Dict] = None, streaming: bool = False, **nids_kwargs):
        import os
        # Use provided interface or fall back to environment variable or default
        if pfsense_interface is None:
            pfsense_interface = os.getenv('PFSENSE_INTERFACE', 'em1')
        self.pfsense_host, self.pfsense_user = pfsense_host, pfsense_user
        self.pfsense_key, self.pfsense_interface = pfsense_key, pfsense_interface
        self.capture_duration, self.running = capture_duration, False
        self.streaming = streaming  # Parallel capture/analysis mode
        
        self.capture = PfSenseCapture(host=pfsense_host, user=pfsense_user,
                                       interface=pfsense_interface, key_file=pfsense_key)
        self.nids = HybridNIDS(pfsense_host=pfsense_host, pfsense_user=pfsense_user,
                               pfsense_key=pfsense_key, pfsense_interface=pfsense_interface, **nids_kwargs)
        self.action_handler = ActionHandler(config=action_config, pfsense_capture=self.capture)
        self._pending_pcap = None  # For streaming mode
        
        PCAP_DIR.mkdir(parents=True, exist_ok=True)
        FLOWS_DIR.mkdir(parents=True, exist_ok=True)
        logger.info(f"Pipeline: {pfsense_user}@{pfsense_host}, iface={pfsense_interface}, interval={capture_duration}s, streaming={streaming}")
    
    def start(self):
        """Start continuous detection loop"""
        self.running, cycle = True, 0
        mode_name = "Streaming" if self.streaming else "Interval"
        print(f"\n" + "="*60 + f"\n  HYBRID NIDS - Real-time Detection ({mode_name})\n" + "="*60 + "\n")
        
        try:
            if self.streaming:
                self._start_streaming()
            else:
                self._start_interval()
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()
    
    def _start_interval(self):
        """Standard interval-based capture and analysis"""
        cycle = 0
        while self.running:
            cycle += 1
            pcap_file = PCAP_DIR / f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
            
            if not self.capture.capture(self.capture_duration, pcap_file):
                time.sleep(5)
                continue
            
            result = self.nids.analyze(pcap_file)
            self._print_summary(result, cycle)  # Print summary first for visibility
            self.action_handler.process(result)
            self.action_handler.cleanup_expired_blocks()
            pcap_file.unlink(missing_ok=True)
    
    def _start_streaming(self):
        """Parallel capture/analysis - capture next while analyzing current"""
        from concurrent.futures import ThreadPoolExecutor
        cycle = 0
        
        with ThreadPoolExecutor(max_workers=2) as executor:
            # Start first capture
            pcap1 = PCAP_DIR / f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
            capture_future = executor.submit(self.capture.capture, self.capture_duration, pcap1)
            
            while self.running:
                cycle += 1
                # Wait for current capture
                if not capture_future.result():
                    time.sleep(2)
                    pcap1 = PCAP_DIR / f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
                    capture_future = executor.submit(self.capture.capture, self.capture_duration, pcap1)
                    continue
                
                # Start next capture immediately
                pcap2 = PCAP_DIR / f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
                capture_future = executor.submit(self.capture.capture, self.capture_duration, pcap2)
                
                # Analyze previous capture in parallel
                result = self.nids.analyze(pcap1)
                self._print_summary(result, cycle)  # Print summary first for visibility
                self.action_handler.process(result)
                self.action_handler.cleanup_expired_blocks()
                pcap1.unlink(missing_ok=True)
                
                # Swap for next iteration
                pcap1 = pcap2
    
    def stop(self):
        self.running = False
        stats.save()
        print("\n" + "="*60 + "\n  Pipeline stopped.\n" + "="*60)
    
    def _print_summary(self, result: DetectionResult, cycle: int):
        """Print summary of detection results for each cycle"""
        filtered_info = f" (filtered: {result.filtered_count})" if result.filtered_count > 0 else ""
        summary_line = f"[Cycle {cycle}] {result.total_flows} flows in {result.processing_time:.2f}s{filtered_info}"
        
        print(f"\n{summary_line}", flush=True)
        
        if result.detections:
            by_level: Dict[ThreatLevel, int] = {}
            by_attack_type: Dict[str, Dict[str, int]] = {}  # {attack_type: {flows: count, level: ThreatLevel}}
            total_attack_flows = 0
            for d in result.detections:
                by_level[d.threat_level] = by_level.get(d.threat_level, 0) + 1
                total_attack_flows += d.flow_count
                # Group by attack type
                if d.attack_type not in by_attack_type:
                    by_attack_type[d.attack_type] = {'flows': 0, 'level': d.threat_level}
                by_attack_type[d.attack_type]['flows'] += d.flow_count
            
            # Show attack types with flow counts
            attack_details = []
            for attack_type, info in sorted(by_attack_type.items(), key=lambda x: -x[1]['flows']):
                attack_details.append(f"{attack_type} ({info['flows']} flows, {info['level'].name})")
            
            attacks_line = f"  ⚠️  {len(result.detections)} unique attacks ({total_attack_flows} flows):"
            print(attacks_line, flush=True)
            for detail in attack_details:
                print(f"      • {detail}", flush=True)
        else:
            print("  ✓ No attacks", flush=True)
        
        # Also log it so it appears in the log stream (stderr)
        logger.info(summary_line)
    
    def analyze_pcap(self, pcap_file: Path) -> DetectionResult:
        """Analyze single PCAP (offline mode)"""
        result = self.nids.analyze(pcap_file)
        self.action_handler.process(result)
        return result
