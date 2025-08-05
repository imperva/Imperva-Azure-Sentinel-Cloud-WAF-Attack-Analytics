## Imperva WAF Attack Analytics Connector 

### 1. Description

The below readme provides instructions on how to deploy the Imperva WAF Attack Analytics Connector to Azure Sentine.

### 2. Deploying the Connector

The first step is to deploy the Data Connector. 
1. Go to Data Connectors\readme.md and hit the Deploy to Azure Button, while being logged in your target Azure Environment.
2. A custom deployment portal will be presented, indicating that we are deploying it as an ARM template.
3. The following parameters need to be filled:
   
    a. Function Name. This will be the name of the resultant function app name. This is also used to derive the storage account name. Because we are assigning a unique name to the storage account and using a generated string as a suffix, with a limitation of 24 chars for the storage account, the function app name should be no longer than 18 characters.
   
    b. Workspace Id. This is the workspace Id of the corresponding Log Analytics space which has Sentinel on top. Can be retrieved from the "Properties" blade from the associated Log Analytics space.
   
![workspace id and primary key](https://github.com/GabrielNBJJ/impervaWafAttackAnalyticsSentinelSolution/assets/58338986/b24cf957-8071-44fe-91da-1d393811bdd2)


    c. Workspace Key. The primary or secondary key associated with the Log Analytics space. Can be retrieved from the "Agent" blade on the associated Log Analytics space.

![workspace id and primary key](https://github.com/GabrielNBJJ/impervaWafAttackAnalyticsSentinelSolution/assets/58338986/b24cf957-8071-44fe-91da-1d393811bdd2)
   
    d. Imperva API ID, Imperva API Key and Imperva Log Server URI are all values that are retrieved from the Imperva portal. Head to Account Management/SIEM Logs/Attack Analytics Log Setup to retrieve the corresponding values.
   
5. Pick a resource group and hit then deploy.


Once deployed, the connector is configured to check for new events every 15 minutes and push them to the ImpervaWAFAttackAnalytics_CL custom table in the target log analytics space.

### Warning

Within testing, we've noticed some delay from the point of events being ingested to the point of them showing up correctly parsed in the portal.

### 3. Deploy the Workbook

1. Go to Workbooks\readme.md and hit the Deploy to Azure Button, while being logged in your target Azure Environment.
2. A custom deployment portal will be presented, indicating that we are deploying it as an ARM template.
3. The following parameters need to be filled:
    a. workbookDisplayName. This is simply how the workbook will show in the console. Can leave default or use an arbitrary string as desired.
   
    b. workbookType. Leave this with "sentinel" populated.
   
    c. workbookSourceId. Provide the full resource Id path of the associated log analytics space. Can be retrieved from the "Properties" blade of the associated log analytics space. See screenshot.
   ![log analytics properties](https://github.com/GabrielNBJJ/impervaWafAttackAnalyticsSentinelSolution/assets/58338986/bfcff020-6ad5-4c2f-9477-86811c901f81)

    d. workbookId. Leave the formula as is.
5. Proceed an deploy.
6. The workbook will be visible within Workbooks in Sentinel.


### 4. Deploy the analytic rule.

Requirements: For this to work, the custom table must have been created by the function. This means some events must have been ingested. Check in Sentinel if the custom table exists, otherwise the deployment will fail indicating a missing table.

1. Go to Workbooks\readme.md and hit the Deploy to Azure Button, while being logged in your target Azure Environment.
2. A custom deployment portal will be presented, indicating that we are deploying it as an ARM template.
3. The following parameters need to be filled:
    a. sentinel_workspace_name. Simply provide the name of the Sentinel space.
4. Proceed an deploy.
