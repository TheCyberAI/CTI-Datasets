from datasets import load_dataset, DatasetDict
import os

# 1. Configuration
INPUT_FILE = "cti_fine_tuning_dataset.json"
HF_USERNAME = "YourUsername"  # Replace with your Hugging Face username if pushing
DATASET_NAME = "CTI-CyberSentinel-v1"

def convert_and_prepare_dataset():
    print(f"Loading {INPUT_FILE} into Hugging Face format...")
    
    # --- Step 1: Load the JSON file ---
    # The 'json' loader automatically handles list-of-dicts structures
    raw_dataset = load_dataset("json", data_files=INPUT_FILE, split="train")
    
    print(f"Loaded {len(raw_dataset)} rows.")
    print("Sample structure:", raw_dataset.features)

    # --- Step 2: Create Train/Test Splits (Recommended) ---
    # It is best practice to split data to verify the model isn't just memorizing
    # Here we use 90% for training, 10% for testing
    train_testvalid = raw_dataset.train_test_split(test_size=0.1, seed=42)
    
    # Organize into a DatasetDict (Standard HF structure)
    dataset = DatasetDict({
        'train': train_testvalid['train'],
        'test': train_testvalid['test']
    })
    
    print("\nDataset Structure:")
    print(dataset)
    
    # --- Step 3: Save or Push ---
    
    # Option A: Save locally (Faster for re-loading later)
    local_path = "./cti_huggingface_dataset"
    dataset.save_to_disk(local_path)
    print(f"\n[v] Saved locally to '{local_path}'")
    print("    To use later: dataset = load_from_disk('./cti_huggingface_dataset')")

    # Option B: Push to Hugging Face Hub (For sharing or use in other environments)
    # Uncomment the lines below to push (requires 'huggingface-cli login')
    
    # repo_id = f"{HF_USERNAME}/{DATASET_NAME}"
    # print(f"\nPushing to Hugging Face Hub: {repo_id}...")
    # dataset.push_to_hub(repo_id)
    # print(f"[v] Pushed successfully! View at: https://huggingface.co/{repo_id}")

    return dataset

if __name__ == "__main__":
    if os.path.exists(INPUT_FILE):
        final_dataset = convert_and_prepare_dataset()
        
        # Verify one entry
        print("\n--- Sample Entry (Train Split) ---")
        print(final_dataset['train'][0])
    else:
        print(f"Error: {INPUT_FILE} not found. Run the generation script first.")cti_huggingface_dataset
