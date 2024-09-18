import sys, os, sqlite3, json
from packaging import version
from lxml import etree
from database import create_database

# setup filenames and variables 
pom_file= ""
db_file = "vulnerabilities.sqlite"
error_found = 0

# check that we have the proper number of arguments and the correct inputs for the first one 
if len(sys.argv) > 2:
    if sys.argv[1] == 'doAll':
        # delete the old database 
        # if os.path.exists(db_file): # uncomment for submisson!!!!
        #     os.remove(db_file)
        # create the database anew
        create_database(db_file)
    elif sys.argv[1] == "detectOnly":
        # otherwise we need no futher setup, but need to confim that it is a valid argument
        pass
    else: 
        # otherwise tell the user they are wrong 
        print("invalid mode parameter '{sys.argv[1]}', please enter \'doAll\' or \'detectOnly\'")
else:
    # general message notifying the user they have enter invalid input
    print("invalid parameters, you must have a mode selected a and pom file referenced")
    
# read and parse the pom file with sys and lxml
pom_file = sys.argv[2]
dependency_tree = etree.parse(pom_file,  parser=etree.XMLParser(remove_comments=True))
root = dependency_tree.getroot()

# connect ot the database
con = sqlite3.connect(db_file)
cur = con.cursor()

# loop through the dependencies to check for vulnerabilities 
for dependencies in root.findall('dependencies', root.nsmap):  
    for dependency in dependencies:
       
        # Get group id to filter descriptions and/or references by the package group
        groupId = dependency[0].text
        if '.' in groupId:
            group_parts = groupId.split(".")[1]
            groupId = group_parts[1] if len(group_parts) > 1 else groupId
        
        # Get artifact id to filter for artifact 
        artifactId = dependency[1].text
        
        # Get the version of the dependency to compare to the vulnerability version ranges
        dependency_version = version.parse(dependency[2].text)
        
        # Get results from the database 
        cur.execute(f'SELECT configurations, cve_id, metrics FROM "vulnerabilities" WHERE (configurations LIKE "%{artifactId}%" AND (descriptions LIKE "%{groupId}%" OR reference LIKE "%{groupId}%"))')
        results = cur.fetchall()
        
        
        if results: # If we have vulnerabilities for this dependency   
                    # loop through each vulnerability 
                    
            
            
            for vulnerability in results: 
                # parse the recieved data
                parsed_vulnerability = json.loads(vulnerability[0])[0]['nodes'][0]['cpeMatch'][0] 
                
                # read the ID 
                cve_id = vulnerability[1] 
                
                # read the metrics
                metrics = json.loads(vulnerability[2])
                # if there is V3.1 data, read that, otherwise read V2 data
                try:
                    severity = metrics['cvssMetricV31'][0]['cvssData']['baseSeverity']
                except:
                    severity = metrics['cvssMetricV2'][0]['baseSeverity']
                
                # if there is a start or end date, read those, otherwise set to "0" and "9999" for comparisons
                # this can fail if versioning is irregular
                
                # also check if these are inclusive or exclusive
                start_including = 1
                try:
                    vulnerability_version_start = version.parse(parsed_vulnerability['versionStartIncluding'])
                except:
                    try:
                        vulnerability_version_start = version.parse(parsed_vulnerability['versionStartExcluding'])
                        start_including = 0
                    except:
                        vulnerability_version_start = version.parse("0.0")
                    
                end_including = 0
                try:
                    vulnerability_version_end = version.parse(parsed_vulnerability['versionEndExcluding'])
                except:
                    try:
                        vulnerability_version_end = version.parse(parsed_vulnerability['versionEndIncluding'])
                        end_including = 1
                    except:
                        vulnerability_version_end = version.parse("9999.9999")
                
                # check if our dependency falls within the vulnerability timeframe
                # this could be better. it is not :( 
                if (start_including and not end_including and (vulnerability_version_start <= dependency_version < vulnerability_version_end)) :
                    # print this part once, only if we find a vulnerability
                    if not error_found:
                        error_found = 1
                        print("Known security vulnerabilities detected:\n")
                        
                    # print the dependency and vulnerability info
                    print(f'Dependency: {artifactId}')
                    print(f'Version(s): >= {vulnerability_version_start} < {vulnerability_version_end}')
                    print(f'Vulnerabilities:')
                    print(f'- {cve_id} ({severity.capitalize()} Severity)\n')
                    
                elif (not start_including and end_including and (vulnerability_version_start < dependency_version <= vulnerability_version_end)):
                    
                    # print this part once, only if we find a vulnerability
                    if not error_found:
                        error_found = 1
                        print("Known security vulnerabilities detected:\n")
                        
                    # print the dependency and vulnerability info
                    print(f'Dependency: {artifactId}')
                    print(f'Version(s): > {vulnerability_version_start} <= {vulnerability_version_end}')
                    print(f'Vulnerabilities:')
                    print(f'- {cve_id} ({severity.capitalize()} Severity)\n')
                    
                elif ( start_including and end_including and (vulnerability_version_start <= dependency_version <= vulnerability_version_end)):
                    # print this part once, only if we find a vulnerability
                    if not error_found:
                        error_found = 1
                        print("Known security vulnerabilities detected:\n")
                        
                    # print the dependency and vulnerability info
                    print(f'Dependency: {artifactId}')
                    print(f'Version(s): >= {vulnerability_version_start} <= {vulnerability_version_end}')
                    print(f'Vulnerabilities:')
                    print(f'- {cve_id} ({severity.capitalize()} Severity)\n')
                    
                elif (not start_including and not end_including and (vulnerability_version_start < dependency_version < vulnerability_version_end)):
                    # print this part once, only if we find a vulnerability
                    if not error_found:
                        error_found = 1
                        print("Known security vulnerabilities detected:\n")
                        
                    # print the dependency and vulnerability info
                    print(f'Dependency: {artifactId}')
                    print(f'Version(s): > {vulnerability_version_start} < {vulnerability_version_end}')
                    print(f'Vulnerabilities:')
                    print(f'- {cve_id} ({severity.capitalize()} Severity)\n')
                    