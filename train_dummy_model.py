# train_dummy_model.py
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

# Improved patch texts and labels for better detection!
texts = [
    "security patch fixes vulnerability",
    "update to improve UI design",
    "critical security update for system",
    "minor bug fix for user interface",
    "vulnerability patch for kernel",
    "buffer overflow fix in login",
    "add new profile feature",
    "SQL injection vulnerability patch applied",
    "update software version",
    "XSS vulnerability fix in comments",
    "safe refactor of dashboard",
    "path traversal exploit fixed",
    "authentication bypass patched",
    "change font size for better UX",
    "DoS vulnerability mitigated",
    "update user profile image feature",
    "fixes for memory leak issue",
    "regular update - improves performance",
    "security: prevent privilege escalation",
    "UI update with new color scheme"
]
labels = [
    "security", "non-security", "security", "non-security", "security",
    "security", "non-security", "security", "non-security", "security",
    "non-security", "security", "security", "non-security", "security",
    "non-security", "security", "non-security", "security", "non-security"
]

# Vectorize text
vectorizer = TfidfVectorizer(max_features=1000)
X = vectorizer.fit_transform(texts)

# Train model
model = LogisticRegression()
model.fit(X, labels)

# Save model and vectorizer to 'model/' folder
joblib.dump(model, "model/patch_classifier.pkl")
joblib.dump(vectorizer, "model/tfidf_vectorizer.pkl")
print("✅ Improved model and vectorizer saved!")
