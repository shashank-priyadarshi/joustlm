# Software Engineer Take-Home Assignment - Jouster

### **Assignment: "LLM Knowledge Extractor"**

We’d like you to build a small prototype that takes in text and uses an LLM to produce both a summary and structured data. This exercise is designed to see how you structure a small but complete system, not how many features you can cram in. Please timebox to ~90 minutes (max 2 hours).

---

### **Core Requirements (60–90 mins)**

- **Input & Processing**
    - Accept a block of unstructured text input (e.g., an article, blog post, or update).
    - Use an LLM (OpenAI, Claude, or a mock wrapper if you prefer) to:
        - Generate a **1–2 sentence summary**.
        - Extract structured metadata as JSON with at least:
            - `title` (if available)
            - `topics` (3 key topics)
            - `sentiment` (positive / neutral / negative)
            - `keywords` (the 3 most frequent nouns in the text — implement yourself, not via the LLM)
- **Persistence**
    - Store all analyses in a lightweight database (SQLite, Postgres, Supabase, etc.).
- **API or UI**
    - Provide either:
        - An API with endpoints:
            - `POST /analyze` → process new text, store + return result
            - `GET /search?topic=xyz` → return all stored analyses with matching topic/keyword
        - OR a minimal web UI that supports submitting text, viewing past analyses, and searching.
- **Robustness**
    - Handle at least two edge cases:
        - Empty input
        - LLM API failure (e.g., return an error message instead of crashing)

---

### Bonus (optional, if you have time)

- Add basic tests (unit or integration).
- Containerize with Docker.
- Support batch processing (multiple texts at once).
- Include a “confidence score” in the JSON (even a naive heuristic).

---

### Language Guidance

You may use any language you’re comfortable with.

- **Python** will likely be fastest.
- **Go** is also welcome if that’s your strength — we know they require more setup.

---

### Deliverables

A **README** that includes:

- Setup and run instructions.
- A **3–5 sentence explanation** of your design choices (why you structured the code this way, why you chose these tools).
- Any trade-offs you made because of time.

---

### Timebox

- Please spend **no more than 2 hours total**.
- We value clarity, judgment, and working code over completeness or polish.

---

### Submission

Submit a GitHub repo link or a Google Drive link containing your project, along with your application details here: [Assignment Submission](https://www.notion.so/2615c65e6f0d8172bf68ffdd828c09f4?pvs=21) 

---

### Update Timeline

Upon receiving your submission, we will review it and update you within **5 working days** *if we **don’t** believe you’re a good fit.*

If you don’t hear from us within 5 working days, consider it a good sign! You are advancing to the next step - a 30-min interview. We schedule the interviews based on **first-submit, first-interview** order to ensure fairness. We’re a small team so it might take some time for us to reach out to you. But please rest assure that you will be contacted for the interview.