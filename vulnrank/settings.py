import pathlib

RISK_CLASS_GT = pathlib.Path("user_assessments/output_gt_class")
FEATURES_FILE_CLASS_GT = pathlib.Path("finding_features/output_gt_class")
RISK_CLASS_RESIDENTES = pathlib.Path("user_assessments/output_residentes_class")
FEATURES_FILE_CLASS_RESIDENTES = pathlib.Path("finding_features/output_residentes_class")
RISK_NUM_RESIDENTES = pathlib.Path("user_assessments/output_residentes_num")
FEATURES_FILE_NUM_RESIDENTES = pathlib.Path("finding_features/output_residentes_num")
RESULT_ID_TO_CRIVO = pathlib.Path("data/join-deployments/result_id_to_crivos.json")
JSON_USERS_TO_EMAIL = pathlib.Path("data/join-deployments/users.json")
CVE2META_PICKLE_FP = pathlib.Path("data/cve-metadata/cve2meta.pkl.gz")
GRAPHS_OUTDIR = pathlib.Path("report_graphs")
FRACTIONS = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]
ITERATIONS = 10
TARGET_COLUMN = "ranking"
CLASSIFICATION_THRESHOLD = 0.6
SEVERITY_LABELS = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Info": 0,
    "Undefined": -1,
}