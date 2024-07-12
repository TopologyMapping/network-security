import json
import pandas as pd
from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt
from xgboost import XGBRegressor
from sklearn.metrics import mean_squared_error

with open('ip_data.json', 'r') as json_file:
    data = json.load(json_file)

def extract_features(data_point):
    num_vulns = len(data_point["Vulnerabilities"])
    num_critical = sum(1 for vuln in data_point["Vulnerabilities"] if vuln["Severity"] == "Critical")
    num_high = sum(1 for vuln in data_point["Vulnerabilities"] if vuln["Severity"] == "High")
    return {
        "IP": data_point["IP"],
        "NumVulnerabilities": num_vulns,
        "NumCritical": num_critical,
        "NumHigh": num_high,
        "Score": data_point["Score"],
        "ISP": data_point["ISP"],
        "Location": data_point["Location"],
        "Vote": int(data_point["Vote"]) 
    }

dataset = pd.DataFrame([extract_features(dp) for dp in data])
dataset['ISP'] = dataset['ISP'].astype('category').cat.codes
dataset['Location'] = dataset['Location'].astype('category').cat.codes

X = dataset.drop(columns=["IP", "Score", "NumVulnerabilities"])
y = dataset["Score"]

print("Processed Dataset:")
print(dataset)

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = XGBRegressor(n_estimators=10000, learning_rate=0.1, max_depth=6, verbosity=1)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)

rmse = mean_squared_error(y_test, y_pred, squared=False)
print(f"RMSE: {rmse}")

ranking = pd.DataFrame({'IP': dataset.loc[X_test.index, 'IP'], 'PredictedScore': y_pred})
ranking = ranking.sort_values(by='PredictedScore', ascending=False)

ranking.to_csv('ip_ranking.csv', index=False)

print(ranking)

plt.figure(figsize=(18, 6))

plt.subplot(1, 3, 1)
plt.barh(X.columns, model.feature_importances_)
plt.xlabel('Feature Importance')
plt.title('Feature Importance')

plt.subplot(1, 3, 2)
plt.scatter(y_test, y_pred, alpha=0.3)
plt.plot([y.min(), y.max()], [y.min(), y.max()], 'r--')
plt.xlabel('Actual')
plt.ylabel('Predicted')
plt.title('Predicted vs. Actual Values')

plt.subplot(1, 3, 3)
residuals = y_test - y_pred
plt.scatter(y_pred, residuals, alpha=0.3)
plt.hlines(0, y_pred.min(), y_pred.max(), colors='r', linestyles='--')
plt.xlabel('Predicted')
plt.ylabel('Residuals')
plt.title('Residuals Plot')

plt.tight_layout()
plt.show()

def rank_new_ips(new_data):
    new_dataset = pd.DataFrame([extract_features(dp) for dp in new_data])
    new_dataset['ISP'] = new_dataset['ISP'].astype('category').cat.codes
    new_dataset['Location'] = new_dataset['Location'].astype('category').cat.codes
    columns_to_drop = [col for col in ["IP", "Score", "NumVulnerabilities"] if col in new_dataset.columns]
    X_new = new_dataset.drop(columns=columns_to_drop)
    y_new_pred = model.predict(X_new)
    
    new_ranking = pd.DataFrame({'IP': new_dataset['IP'], 'PredictedScore': y_new_pred})
    new_ranking = new_ranking.sort_values(by='PredictedScore', ascending=False)
    return new_ranking

new_ip_data = [
    {
        "IP": "192.168.1.10",
        "Location": "New York, USA",
        "ISP": "ISP Example",
        "LastSeen": "2024-07-08T12:34:56",
        "Vulnerabilities": [
            {"ID": "CVE-2024-1234", "Severity": "Critical"},
            {"ID": "CVE-2024-2345", "Severity": "High"},
            {"ID": "CVE-2024-3456", "Severity": "Medium"}
        ],
        "Score": 5.0,
        "Vote": 1
    },
    {
        "IP": "103.105.171.173",
        "Location": "Malloryside",
        "ISP": "Scott Inc",
        "LastSeen": "2024-05-18T08:53:03",
        "Vulnerabilities": [
            {"ID": "CVE-1975-6994", "Severity": "Low"},
            {"ID": "CVE-1993-7502", "Severity": "High"},
            {"ID": "CVE-1981-6736", "Severity": "Medium"}
        ],
        "Score": 6,
        "Vote": 0
    },
    {
        "IP": "212.180.93.19",
        "Location": "Port Dustinmouth",
        "ISP": "Miller Group",
        "LastSeen": "2024-04-04T12:26:25",
        "Vulnerabilities": [
            {"ID": "CVE-2016-4890", "Severity": "Critical"},
            {"ID": "CVE-1995-5505", "Severity": "Critical"},
            {"ID": "CVE-1997-5420", "Severity": "Medium"},
            {"ID": "CVE-1974-2245", "Severity": "High"},
            {"ID": "CVE-1976-9848", "Severity": "Critical"}
        ],
        "Score": 17,
        "Vote": 1
    },
        {
        "IP": "213.181.93.19",
        "Location": "Porta Dustinmouth",
        "ISP": "Milledr Group",
        "LastSeen": "2024-04-04T12:27:25",
        "Vulnerabilities": [
            {"ID": "CVE-2016-4890", "Severity": "Critical"},
            {"ID": "CVE-1995-5505", "Severity": "Critical"},
            {"ID": "CVE-1974-2245", "Severity": "High"},
            {"ID": "CVE-1976-9848", "Severity": "Critical"}
        ],
        "Score": 1,
        "Vote": 1
    },
]

new_ip_ranking = rank_new_ips(new_ip_data)
print("New IP Ranking:")
print(new_ip_ranking)
