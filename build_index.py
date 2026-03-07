import os
import faiss
import numpy as np
import pickle
from sentence_transformers import SentenceTransformer

MODEL = SentenceTransformer("all-MiniLM-L6-v2")

docs = []
paths = []

print("Scanning knowledge folder...")

# chunk size improves retrieval accuracy
CHUNK_SIZE = 800

for root, dirs, files in os.walk("knowledge"):
    for file in files:

        if not file.endswith((".txt", ".md")):
            continue

        path = os.path.join(root, file)

        try:
            with open(path, "r", encoding="utf8", errors="ignore") as f:
                text = f.read()
        except Exception as e:
            print("Skipping:", path, e)
            continue

        # split long files into chunks
        for i in range(0, len(text), CHUNK_SIZE):

            chunk = text[i:i + CHUNK_SIZE]

            if chunk.strip():
                docs.append(chunk)
                paths.append(path)

        if len(docs) % 500 == 0:
            print(f"Loaded {len(docs)} chunks...")

if not docs:
    raise RuntimeError("No documents found in knowledge folder.")

print(f"\nTotal chunks indexed: {len(docs)}")

print("\nGenerating embeddings...")

embeddings = MODEL.encode(
    docs,
    batch_size=32,
    show_progress_bar=True
)

embeddings = np.array(embeddings).astype("float32")

print("Building FAISS index...")

dim = embeddings.shape[1]

index = faiss.IndexFlatL2(dim)

index.add(embeddings)

print("Saving index...")

faiss.write_index(index, "exploit_index.faiss")

with open("exploit_docs.pkl", "wb") as f:
    pickle.dump((docs, paths), f)

print("\nIndex built successfully.")