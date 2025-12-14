#  AI Web Application Firewall (WAF) Project

This is the basic structure of the firewall project we will be working on.  
*The data files used to train the RandomForest model are not yet added due to size constraints.*

  
##  Setup Instructions
Please install the required dependencies before running the project.


##  How to Run the Project
### 🔹 Run the Backend App

```bash
cd backend_app
python app.py
```
### 🔹 Run the WAF

```bash
cd waf
python app.py
```

##  Server Info

Both servers will run on localhost for now.
All incoming requests will be logged to a MongoDB server running locally.

Please make sure MongoDB is running on your machine before testing — either using MongoDB Compass or the terminal.

---

## Testing the Setup
| URL                                                                             | Description                                                                   |
| ------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| ```http://localhost:5000```                                                     | Should show: `"Welcome to the REAL backend!"`                                 |
| ```http://localhost:5000/search```                                              | Should show: `"Search endpoint reached"`                                      |
| ```http://localhost:5000/login -d "username=admin' OR 1=1 --&password=123"```   | Should return **403 Forbidden** due to WAF blocking the SQL injection attempt |
---

## Note

Ensure that MongoDB is running on localhost before starting the project.

All requests (allowed or blocked) are logged to MongoDB for further analysis.

---
