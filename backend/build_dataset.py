import pandas as pd
import os

def build_final_dataset():
    print("Loading raw datasets...")
    
    # 1. OpenPhish (Phishing) - Usually a flat text file with one URL per line
    try:
        openphish = pd.read_csv("data/raw/openphish.txt", header=None, names=["url"])
        openphish["type"] = "phishing"
        print(f"Loaded {len(openphish)} OpenPhish URLs.")
    except Exception as e:
        print(f"[WARN] Could not load openphish.txt: {e}")
        openphish = pd.DataFrame(columns=["url", "type"])

    # 2. PhishTank (Phishing) - Usually a CSV with a 'url' column
    try:
        phishtank = pd.read_csv("data/raw/phishtank.csv")
        # Ensure we only grab the url column
        if "url" in phishtank.columns:
            phishtank = phishtank[["url"]].copy()
        else:
            # Fallback if the column is named differently (like 'phish_detail_url')
            phishtank = phishtank.iloc[:, 1:2] 
            phishtank.columns = ["url"]
            
        phishtank["type"] = "phishing"
        print(f"Loaded {len(phishtank)} PhishTank URLs.")
    except Exception as e:
        print(f"[WARN] Could not load phishtank.csv: {e}")
        phishtank = pd.DataFrame(columns=["url", "type"])

    # 3. Tranco (Legitimate) - Usually a top 1M site ranking CSV (Rank, Domain)
    try:
        tranco = pd.read_csv("data/raw/tranco.csv", header=None, names=["rank", "url"])
        tranco["type"] = "legitimate"
        tranco = tranco[["url", "type"]]
        print(f"Loaded {len(tranco)} Tranco (Legitimate) URLs.")
    except Exception as e:
        print(f"[WARN] Could not load tranco.csv: {e}")
        tranco = pd.DataFrame(columns=["url", "type"])

    # 4. Kaggle (Mixed) - A pre-made CSV usually containing 'url' and 'type' or 'label'
    try:
        kaggle = pd.read_csv("data/raw/kaggle.csv")
        # Standardize column names
        kaggle.columns = kaggle.columns.str.lower()
        
        # If Kaggle uses 0/1 or 'bad'/'good' instead of 'phishing'/'legitimate'
        if "label" in kaggle.columns and "type" not in kaggle.columns:
            kaggle["type"] = kaggle["label"].apply(
                lambda x: "phishing" if str(x).lower() in ["1", "bad", "phishing"] else "legitimate"
            )
        
        kaggle = kaggle[["url", "type"]]
        print(f"Loaded {len(kaggle)} Kaggle URLs.")
    except Exception as e:
        print(f"[WARN] Could not load kaggle.csv: {e}")
        kaggle = pd.DataFrame(columns=["url", "type"])

    print("\nMerging all datasets into one...")
    # Combine all into one massive dataframe
    final_df = pd.concat([openphish, phishtank, tranco, kaggle], ignore_index=True)

    # Clean the data: drop empty rows and remove duplicates
    initial_count = len(final_df)
    final_df.dropna(subset=["url"], inplace=True)
    final_df.drop_duplicates(subset=["url"], inplace=True)
    
    # Ensure processed directory exists
    os.makedirs("data/processed", exist_ok=True)

    # Save to the processed folder
    output_path = "data/processed/final_dataset.csv"
    final_df.to_csv(output_path, index=False)
    
    print("\n===================================")
    print(f"[OK] Final dataset created successfully: {output_path}")
    print(f"Total Unique URLs: {len(final_df)} (Removed {initial_count - len(final_df)} duplicates/blanks)")
    print("Class Distribution:")
    print(final_df["type"].value_counts())
    print("===================================")

if __name__ == "__main__":
    build_final_dataset()