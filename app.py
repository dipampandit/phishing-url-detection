from flask import Flask, request, render_template
import numpy as np
import pickle
import warnings
from feature import FeatureExtraction

warnings.filterwarnings("ignore")

app = Flask(__name__)

# ── Load the combined model bundle ──────────────────────────────────────
# phishguard_models.pkl structure:
#   {
#     "models":          {"Logistic Regression": ..., "Decision Tree": ...,
#                         "Random Forest": ..., "SVM": ..., "XGBoost": ...},
#     "best_model_name": "Random Forest",
#     "cv_f1_scores":    {...},
#     "feature_names":   [...],
#   }
#
# All models were trained with binary labels:
#   0 = Legitimate / Genuine
#   1 = Phishing
# So for predict_proba:  [prob_genuine, prob_phishing]
# ────────────────────────────────────────────────────────────────────────
_bundle      = pickle.load(open("model/phishguard_models.pkl", "rb"))
_all_models  = _bundle["models"]
_cv_f1       = _bundle["cv_f1_scores"]

# Use the top-3 probabilistic models for the ensemble
ENSEMBLE_MODELS = [
    ("Random Forest",  _all_models["Random Forest"]),
    ("XGBoost",        _all_models["XGBoost"]),
    ("Decision Tree",  _all_models["Decision Tree"]),
]


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        extractor      = FeatureExtraction(url)
        x              = np.array(extractor.getFeaturesList()).reshape(1, 30)
        feature_details = extractor.getFeatureExplanations()

        # ── Per-model predictions ─────────────────────────────────────────
        # predict_proba returns [prob_class0, prob_class1]
        #   class 0 → Genuine,  class 1 → Phishing
        models_breakdown = []
        for name, model in ENSEMBLE_MODELS:
            probs      = model.predict_proba(x)[0]   # [prob_genuine, prob_phishing]
            genuine_p  = float(probs[0])
            phishing_p = float(probs[1])
            models_breakdown.append({
                "name":       name,
                "safe_prob":  round(genuine_p  * 100, 2),
                "phish_prob": round(phishing_p * 100, 2),
                "verdict":    "Genuine" if genuine_p >= 0.5 else "Phishing",
                "f1":         round(_cv_f1.get(name, 0) * 100, 1),
            })

        # ── Ensemble average (weighted by CV F1) ──────────────────────────
        total_f1  = sum(m["f1"] for m in models_breakdown)
        if total_f1 > 0:
            avg_safe = round(
                sum(m["safe_prob"] * m["f1"] for m in models_breakdown) / total_f1, 2
            )
        else:
            avg_safe = round(
                sum(m["safe_prob"] for m in models_breakdown) / len(models_breakdown), 2
            )

        avg_phish      = round(100.0 - avg_safe, 2)
        overall_verdict = "GENUINE" if avg_safe >= 50.0 else "PHISHING"

        # ── Feature counts ────────────────────────────────────────────────
        safe_count   = sum(1 for f in feature_details if f["value"] ==  1)
        warn_count   = sum(1 for f in feature_details if f["value"] ==  0)
        danger_count = sum(1 for f in feature_details if f["value"] == -1)

        return render_template(
            "index.html",
            analyzed=True,
            url=url,
            avg_safe=avg_safe,
            avg_phish=avg_phish,
            overall_verdict=overall_verdict,
            models=models_breakdown,
            features=feature_details,
            counts={"safe": safe_count, "warn": warn_count, "danger": danger_count},
        )

    return render_template("index.html", analyzed=False)


if __name__ == "__main__":
    app.run(debug=True)