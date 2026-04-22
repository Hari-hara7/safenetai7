# safenetai7

# safenetai7

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Train AI models
python train/train_email_model.py
python train/train_link_model.py
python train/train_doc_model.py

# Start API server
python -m uvicorn app.main:app --reload


