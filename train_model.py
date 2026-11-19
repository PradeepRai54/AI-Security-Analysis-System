
import pandas as pd
import numpy as np
import pickle
import warnings

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.feature_extraction.text import TfidfVectorizer

from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.naive_bayes import MultinomialNB

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    fbeta_score,
    classification_report,
    confusion_matrix
)

from preprocessing import text_preprocessing

warnings.filterwarnings("ignore")


# ----------------------------------
# LOAD DATASET
# ----------------------------------

data = pd.read_csv("spam.csv", encoding="latin-1")

data = data.rename(
    columns={
        "v1": "label",
        "v2": "message"
    }
)

data = data[["label", "message"]].dropna()

data = data.drop_duplicates()

data["label"] = data["label"].replace({
    "ham": "Not Spam",
    "spam": "Spam"
})

data["transformed_text"] = data["message"].apply(
    text_preprocessing
)

data = data[data["transformed_text"].str.strip() != ""]

X = data["transformed_text"]
y = data["label"]

encoder = LabelEncoder()
y = encoder.fit_transform(y)

SPAM_CLASS = int(encoder.transform(["Spam"])[0])

print("\nDataset loaded successfully")
print("Total messages:", len(data))
print("Classes:", dict(zip(encoder.classes_, encoder.transform(encoder.classes_))))


# ----------------------------------
# STRATIFIED DATA SPLITTING
# ----------------------------------

X_train_val, X_test, y_train_val, y_test = train_test_split(
    X,
    y,
    test_size=0.15,
    random_state=42,
    stratify=y
)

X_train, X_val, y_train, y_val = train_test_split(
    X_train_val,
    y_train_val,
    test_size=0.1765,
    random_state=42,
    stratify=y_train_val
)

print("\nTraining records:", len(X_train))
print("Validation records:", len(X_val))
print("Testing records:", len(X_test))


# ----------------------------------
# WORD + CHARACTER TF-IDF
# ----------------------------------

def create_vectorizer():

    return FeatureUnion([
        (
            "word",
            TfidfVectorizer(
                analyzer="word",
                ngram_range=(1, 2),
                max_features=15000,
                sublinear_tf=True,
                min_df=1
            )
        ),
        (
            "character",
            TfidfVectorizer(
                analyzer="char",
                ngram_range=(3, 5),
                max_features=15000,
                sublinear_tf=True,
                min_df=2
            )
        )
    ])


# ----------------------------------
# MODEL CONFIGURATION
# ----------------------------------

models = {
    "Logistic Regression": LogisticRegression(
        max_iter=2000,
        class_weight="balanced",
        C=1.0,
        random_state=42
    ),

    "Linear SVM": LinearSVC(
        class_weight="balanced",
        C=1.0,
        random_state=42
    ),

    "Multinomial Naive Bayes": MultinomialNB(
        alpha=0.5
    )
}


# ----------------------------------
# THRESHOLD OPTIMIZATION
# ----------------------------------

def get_model_scores(model, X_data):

    if hasattr(model, "predict_proba"):
        return model.predict_proba(X_data)[:, SPAM_CLASS]

    return model.decision_function(X_data)


def optimize_threshold(y_true, scores):

    best_threshold = None
    best_f2 = -1

    for threshold in np.unique(
        np.quantile(scores, np.linspace(0.05, 0.95, 100))
    ):

        predictions = (scores >= threshold).astype(int)

        precision = precision_score(
            y_true,
            predictions,
            pos_label=SPAM_CLASS,
            zero_division=0
        )

        recall = recall_score(
            y_true,
            predictions,
            pos_label=SPAM_CLASS,
            zero_division=0
        )

        f2 = fbeta_score(
            y_true,
            predictions,
            beta=2,
            pos_label=SPAM_CLASS,
            zero_division=0
        )

        # Avoid choosing a model that flags too many
        # legitimate messages as spam.

        if precision >= 0.80 and f2 > best_f2:

            best_f2 = f2
            best_threshold = threshold

    return best_threshold, best_f2


# ----------------------------------
# TRAIN AND COMPARE MODELS
# ----------------------------------

results = []
trained_models = {}

print("\nMODEL COMPARISON")
print("=" * 60)

for name, classifier in models.items():

    pipeline = Pipeline([
        ("tfidf", create_vectorizer()),
        ("classifier", classifier)
    ])

    pipeline.fit(X_train, y_train)

    validation_scores = get_model_scores(
        pipeline,
        X_val
    )

    threshold, validation_f2 = optimize_threshold(
        y_val,
        validation_scores
    )

    if threshold is None:
        threshold = 0.5 if name == "Logistic Regression" else 0.0

    validation_predictions = (
        validation_scores >= threshold
    ).astype(int)

    precision = precision_score(
        y_val,
        validation_predictions,
        pos_label=SPAM_CLASS,
        zero_division=0
    )

    recall = recall_score(
        y_val,
        validation_predictions,
        pos_label=SPAM_CLASS,
        zero_division=0
    )

    f1 = f1_score(
        y_val,
        validation_predictions,
        pos_label=SPAM_CLASS,
        zero_division=0
    )

    results.append({
        "Model": name,
        "Precision": precision,
        "Recall": recall,
        "F1 Score": f1,
        "F2 Score": validation_f2,
        "Threshold": threshold
    })

    trained_models[name] = {
        "pipeline": pipeline,
        "threshold": threshold,
        "f2": validation_f2
    }

    print("\n", name)
    print("Precision:", round(precision, 4))
    print("Recall:", round(recall, 4))
    print("F1 Score:", round(f1, 4))
    print("F2 Score:", round(validation_f2, 4))
    print("Threshold:", threshold)


# ----------------------------------
# SELECT BEST MODEL
# ----------------------------------

results_df = pd.DataFrame(results)

print("\nVALIDATION COMPARISON")
print(results_df.to_string(index=False))

best_name = max(
    trained_models,
    key=lambda name: trained_models[name]["f2"]
)

best_threshold = trained_models[best_name]["threshold"]

print("\nSelected model:", best_name)
print("Selected threshold:", best_threshold)


# ----------------------------------
# REFIT ON TRAINING + VALIDATION
# ----------------------------------

best_model = trained_models[best_name]["pipeline"]

best_model.fit(
    X_train_val,
    y_train_val
)


# ----------------------------------
# FINAL TEST EVALUATION
# ----------------------------------

test_scores = get_model_scores(
    best_model,
    X_test
)

test_predictions = (
    test_scores >= best_threshold
).astype(int)

print("\nFINAL TEST RESULTS")
print("=" * 60)

print(
    "Accuracy:",
    round(accuracy_score(y_test, test_predictions), 4)
)

print(
    "Spam Precision:",
    round(
        precision_score(
            y_test,
            test_predictions,
            pos_label=SPAM_CLASS,
            zero_division=0
        ),
        4
    )
)

print(
    "Spam Recall:",
    round(
        recall_score(
            y_test,
            test_predictions,
            pos_label=SPAM_CLASS,
            zero_division=0
        ),
        4
    )
)

print(
    "Spam F1 Score:",
    round(
        f1_score(
            y_test,
            test_predictions,
            pos_label=SPAM_CLASS,
            zero_division=0
        ),
        4
    )
)

print("\nClassification Report:")

print(
    classification_report(
        y_test,
        test_predictions,
        target_names=encoder.classes_,
        zero_division=0
    )
)

print("\nConfusion Matrix:")
print(
    confusion_matrix(
        y_test,
        test_predictions
    )
)


# ----------------------------------
# SAVE IMPROVED MODEL SEPARATELY
# ----------------------------------

with open("spam_model_improved.pkl", "wb") as file:
    pickle.dump(best_model, file)

with open("label_encoder_improved.pkl", "wb") as file:
    pickle.dump(encoder, file)

with open("model_threshold.pkl", "wb") as file:
    pickle.dump(best_threshold, file)

with open("model_results.pkl", "wb") as file:
    pickle.dump(results_df, file)


print("\nImproved model saved successfully.")

print("Files created:")
print("spam_model_improved.pkl")
print("label_encoder_improved.pkl")
print("model_threshold.pkl")
print("model_results.pkl")
