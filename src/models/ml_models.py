import pickle
import logging
import numpy as np
from pathlib import Path
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler

# torch is optional — app works fully without it (only legacy classes need it)
try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    logging.getLogger(__name__).warning(
        "PyTorch not installed — LogAnomalyDetector / ImageAnalyzer / TextAnalyzer "
        "are disabled. Core network analysis works fine."
    )

logger = logging.getLogger(__name__)

# ── Saved model directory ─────────────────────────────────────────────────────
SAVED_DIR = Path(__file__).parent / "saved"


def _load_pkl(filename):
    """Load a pickled file from the saved directory, return None if missing."""
    path = SAVED_DIR / filename
    if path.exists():
        with open(path, "rb") as f:
            return pickle.load(f)
    return None


# ─────────────────────────────────────────────────────────────────────────────
class AnomalyDetector:
    """
    Wraps the IsolationForest.
    If a pre-trained model is found on disk (saved by train_ai.py) it is
    loaded automatically; otherwise falls back to on-the-fly training.
    """

    def __init__(self):
        saved_model  = _load_pkl("isolation_forest.pkl")
        saved_scaler = _load_pkl("scaler.pkl")

        if saved_model and saved_scaler:
            self.model      = saved_model
            self.scaler     = saved_scaler
            self.is_trained = True
            logger.info("✔ AnomalyDetector: loaded pre-trained IsolationForest from disk")
        else:
            logger.warning("AnomalyDetector: no saved model found — will train on first sample")
            self.model = IsolationForest(
                n_estimators=200,
                contamination=0.05,
                random_state=42,
            )
            self.scaler     = StandardScaler()
            self.is_trained = False

    def train(self, data):
        """Train / retrain the anomaly detection model."""
        try:
            if len(data.shape) == 1:
                data = data.reshape(1, -1)
            scaled = self.scaler.fit_transform(data)
            self.model.fit(scaled)
            self.is_trained = True
        except Exception as e:
            logger.error(f"Error training anomaly detector: {e}")

    def detect(self, data):
        """Return True if anomaly detected, False otherwise."""
        try:
            if len(data.shape) == 1:
                data = data.reshape(1, -1)

            if not self.is_trained:
                self.train(data)
                return False        # first sample used for training

            # If saved scaler was trained on a different feature count, retrain
            try:
                scaled = self.scaler.transform(data)
            except ValueError:
                logger.info("AnomalyDetector: feature mismatch with saved model — retraining on live data")
                self.is_trained = False
                self.train(data)
                return False

            predictions = self.model.predict(scaled)
            return bool(np.any(predictions == -1))
        except Exception as e:
            logger.debug(f"AnomalyDetector skipped: {e}")
            return False


# ─────────────────────────────────────────────────────────────────────────────
class ThreatClassifier:
    """
    Random Forest classifier trained on labeled network traffic.
    Predicts attack type: Benign / PortScan / DDoS / BruteForce.
    Loaded from disk if train_ai.py has been run.
    """

    def __init__(self):
        saved_clf     = _load_pkl("rf_classifier.pkl")
        saved_scaler  = _load_pkl("scaler.pkl")
        saved_le      = _load_pkl("label_encoder.pkl")
        saved_proto   = _load_pkl("protocol_encoder.pkl")
        saved_flags   = _load_pkl("flags_encoder.pkl")

        if saved_clf and saved_scaler and saved_le:
            self.clf            = saved_clf
            self.scaler         = saved_scaler
            self.label_encoder  = saved_le
            self.protocol_enc   = saved_proto
            self.flags_enc      = saved_flags
            self.is_trained     = True
            logger.info("✔ ThreatClassifier: loaded pre-trained RandomForest from disk")
            logger.info(f"  Classes: {list(saved_le.classes_)}")
        else:
            logger.warning("ThreatClassifier: no saved model found — run train_ai.py first")
            self.clf           = None
            self.scaler        = None
            self.label_encoder = None
            self.protocol_enc  = None
            self.flags_enc     = None
            self.is_trained    = False

    def _encode_protocol(self, protocol: str) -> int:
        if self.protocol_enc:
            try:
                return int(self.protocol_enc.transform([protocol])[0])
            except Exception:
                return 0
        return 0

    def _encode_flags(self, flags: str) -> int:
        if self.flags_enc:
            try:
                return int(self.flags_enc.transform([flags])[0])
            except Exception:
                return 0
        return 0

    def predict(self, record: dict) -> dict:
        """
        Predict the threat class for a single network record.

        record keys expected:
            src_port, dst_port, packet_length, duration,
            protocol, flags, src_ip (str), dst_ip (str)

        Returns dict with 'label', 'confidence', 'probabilities'.
        """
        if not self.is_trained:
            return {"label": "Unknown", "confidence": 0.0, "probabilities": {}}

        try:
            src_ip_oct = int(record.get("src_ip", "0.0.0.0").split(".")[-1])
            dst_ip_oct = int(record.get("dst_ip", "0.0.0.0").split(".")[-1])

            features = np.array([[
                float(record.get("src_port",       0)),
                float(record.get("dst_port",       0)),
                float(record.get("packet_length",  0)),
                float(record.get("duration",       0)),
                float(self._encode_protocol(record.get("protocol", "TCP"))),
                float(self._encode_flags(record.get("flags", "SYN"))),
                float(src_ip_oct),
                float(dst_ip_oct),
            ]])

            scaled     = self.scaler.transform(features)
            pred_idx   = self.clf.predict(scaled)[0]
            pred_proba = self.clf.predict_proba(scaled)[0]

            label      = self.label_encoder.inverse_transform([pred_idx])[0]
            confidence = float(pred_proba[pred_idx])

            probs = {
                cls: float(p)
                for cls, p in zip(self.label_encoder.classes_, pred_proba)
            }

            return {
                "label":         label,
                "confidence":    confidence,
                "probabilities": probs,
            }

        except Exception as e:
            logger.error(f"ThreatClassifier.predict error: {e}")
            return {"label": "Unknown", "confidence": 0.0, "probabilities": {}}


# ─────────────────────────────────────────────────────────────────────────────
# Legacy classes kept for backward compatibility
# ─────────────────────────────────────────────────────────────────────────────

if TORCH_AVAILABLE:
    class LogAnomalyDetector:
        def __init__(self):
            self.model = nn.Sequential(
                nn.Linear(10, 64), nn.ReLU(),
                nn.Linear(64, 32), nn.ReLU(),
                nn.Linear(32, 2),
            )
            self.scaler     = StandardScaler()
            self.is_trained = False

        def _prepare_features(self, log_data):
            features = np.zeros((len(log_data), 10))
            for i, entry in enumerate(log_data):
                features[i] = [
                    entry.get("event_frequency",        0),
                    entry.get("time_of_day",            0),
                    entry.get("severity_level",         0),
                    entry.get("source_ip_count",        0),
                    entry.get("destination_ip_count",   0),
                    entry.get("unique_users",           0),
                    entry.get("error_count",            0),
                    entry.get("warning_count",          0),
                    entry.get("critical_count",         0),
                    entry.get("authentication_failures",0),
                ]
            return features

        def train(self, log_data, labels):
            try:
                features        = self._prepare_features(log_data)
                scaled_features = self.scaler.fit_transform(features)
                X = torch.FloatTensor(scaled_features)
                y = torch.LongTensor(labels)
                criterion = nn.CrossEntropyLoss()
                optimizer = torch.optim.Adam(self.model.parameters())
                for _ in range(100):
                    optimizer.zero_grad()
                    outputs = self.model(X)
                    loss    = criterion(outputs, y)
                    loss.backward()
                    optimizer.step()
                self.is_trained = True
            except Exception as e:
                logger.error(f"Error training log anomaly detector: {e}")

        def detect(self, log_data):
            try:
                features = self._prepare_features([log_data])
                if not self.is_trained:
                    self.scaler.fit(features)
                    self.train([log_data], [0])
                scaled = self.scaler.transform(features)
                X      = torch.FloatTensor(scaled)
                with torch.no_grad():
                    outputs = F.softmax(self.model(X), dim=1)
                return outputs[0][1].item() > 0.5
            except Exception as e:
                logger.error(f"Error detecting log anomalies: {e}")
                return False

    class ImageAnalyzer:
        def __init__(self):
            self.model = nn.Sequential(
                nn.Linear(5, 32), nn.ReLU(),
                nn.Linear(32, 16), nn.ReLU(),
                nn.Linear(16, 2),
            )
            self.scaler = StandardScaler()

        def preprocess_image(self, image):
            try:
                if len(image.shape) == 3:
                    image = np.mean(image, axis=2)
                return image.flatten()
            except Exception as e:
                logger.error(f"Error preprocessing image: {e}")
                return None

        def analyze(self, image):
            try:
                processed = self.preprocess_image(image)
                if processed is None:
                    return {"suspicious": False, "confidence": 0}
                features = self._extract_image_features(processed)
                X = torch.FloatTensor([list(features.values())])
                with torch.no_grad():
                    outputs = F.softmax(self.model(X), dim=1)
                prediction = outputs[0][1].item()
                return {
                    "suspicious":        bool(prediction > 0.5),
                    "confidence":        float(prediction),
                    "features_detected": features,
                }
            except Exception as e:
                logger.error(f"Error analyzing image: {e}")
                return {"suspicious": False, "confidence": 0}

        def _extract_image_features(self, image):
            try:
                return {
                    "mean":   np.mean(image),
                    "std":    np.std(image),
                    "min":    np.min(image),
                    "max":    np.max(image),
                    "median": np.median(image),
                }
            except Exception as e:
                logger.error(f"Error extracting image features: {e}")
                return {}

    class TextAnalyzer:
        def __init__(self):
            self.model = nn.Sequential(
                nn.Linear(5, 32), nn.ReLU(),
                nn.Linear(32, 16), nn.ReLU(),
                nn.Linear(16, 2),
            )

        def analyze(self, text):
            try:
                features = self._extract_text_features(text)
                X = torch.FloatTensor([list(features.values())])
                with torch.no_grad():
                    outputs = F.softmax(self.model(X), dim=1)
                prediction = outputs[0][1].item()
                return {
                    "suspicious": bool(prediction > 0.5),
                    "confidence": float(prediction),
                    "features":   features,
                }
            except Exception as e:
                logger.error(f"Error analyzing text: {e}")
                return {"suspicious": False, "confidence": 0}

        def _preprocess_text(self, text):
            try:
                return text.lower()
            except Exception as e:
                logger.error(f"Error preprocessing text: {e}")
                return ""

        def _extract_text_features(self, text):
            try:
                preprocessed = self._preprocess_text(text)
                return {
                    "length":        len(preprocessed),
                    "word_count":    len(preprocessed.split()),
                    "unique_words":  len(set(preprocessed.split())),
                    "special_chars": sum(not c.isalnum() for c in preprocessed),
                    "numeric_count": sum(c.isdigit() for c in preprocessed),
                }
            except Exception as e:
                logger.error(f"Error extracting text features: {e}")
                return {}

else:
    # Stub classes used when torch is not installed
    class LogAnomalyDetector:
        def __init__(self): pass
        def train(self, *a, **kw): pass
        def detect(self, *a, **kw): return False

    class ImageAnalyzer:
        def __init__(self): pass
        def analyze(self, *a, **kw): return {"suspicious": False, "confidence": 0}

    class TextAnalyzer:
        def __init__(self): pass
        def analyze(self, *a, **kw): return {"suspicious": False, "confidence": 0}