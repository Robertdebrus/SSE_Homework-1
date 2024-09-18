import sqlite3, requests, json
from config import API_KEY

def create_database(db_file):
    # Headers (include your API key here)
    headers = {
        "Accept": "application/json",
        "apiKey": API_KEY  # Add the API key in the headers
    }


    con = sqlite3.connect(db_file)
    cur = con.cursor()
    
    # Initialize pagination parameters
    start_index = 0
    results_per_page = 2000  # Maximum allowed by NVD API
    total_results = 1  # Just a placeholder to enter the loop

    api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    
    while start_index < total_results:
        params = {'startIndex': start_index, 'resultsPerPage': results_per_page}
        response = requests.get(api_url,  headers = headers, params = params)
        
        if response.status_code == 200:
            data = response.json()
            if start_index == 0:
                total_results = data['totalResults']
            # Create the table 
            cur.execute(''' CREATE TABLE IF NOT EXISTS vulnerabilities (
                            cve_id TEXT PRIMARY KEY,
                            descriptions TEXT,
                            source_identifier TEXT,
                            published TEXT,
                            lastModified TEXT,
                            weaknesses TEXT, 
                            configurations TEXT,
                            reference TEXT,
                            metrics TEXT
                        ); ''')

            # Extract relevant data and insert it into the database
            for item in data['vulnerabilities']:
                cve_id = item['cve'].get('id',[])
                descriptions = json.dumps(item['cve'].get('descriptions',[]))
                source_identifier = item['cve'].get('sourceIdentifier',[])
                published = item['cve'].get('published',[])
                lastModified = item['cve'].get('lastModified',[])
                weaknesses = json.dumps(item['cve'].get('weaknesses',[]))
                configurations = json.dumps(item['cve'].get('configurations',[]))
                references = json.dumps(item['cve'].get('references',[]))
                metrics = json.dumps(item['cve'].get('metrics',[]))

                # Insert the data into the SQLite database
                cur.execute('''
                    INSERT OR IGNORE INTO vulnerabilities (cve_id, descriptions, source_identifier, published, lastModified, weaknesses, configurations, reference, metrics)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (cve_id, descriptions, source_identifier, published, lastModified, weaknesses, configurations, references, metrics))
            start_index += results_per_page
            print("next page")

        # Commit and close the database connection
    con.commit()    
    con.close()

    print(f"Data saved to SQLite database successfully!")

    # else:
    #         print(f"Error: {response.status_code}, Message: {response.text}")