# Acronis Agent Deployment
This PowerShell script is intended to be used in a RMM solution (e. g. Solarwinds N-able RMM or Riversuit Riverbird). The installation file is supposed to be hosted on a secure FTP server.

## Step 1
Download the Acronis agents for Windows, Active Directory, Hyper-V and Microsoft SQL from the Acronis Management Portal.

![Acronis Portal](/img/Acronis%20Download.jpg)

![Agent for Windows](/Img/Agent%20for%20Windows.jpg)

![Agent for Active Directory and for Microsoft SQL](/Img/Agent%20for%20SQL%20and%20AD.jpg)

![Agent for Hyper-V](/Img/Agent%20for%20Hyper-V.jpg)

## Step 3
Configure the script with all its parameters in your RMM solution. (The screenshots where taken in Riversuite Riverbird -- your RMM might look different and have a different proccess for this.)

![Example in Riverbird](/Img/Riverbird%20Script%20Config.jpg)

You'll need the following Parameters:

|Variable name|Example value|Explanation|
|---|---|---|
|FtpServerFqdn|contoso.org|FQDN or IP address of your FTP server|
|FtpUsername|user|Username of your FTP user|
|FtpPassword|lkj fa8efjalALKJ38uu!"'ÄÖ|Password for your FTP user|
|FtpAgentDir|\home\BackupAgentInstallFiles\|Directory in which you've stored the agent installation files|
|Dest|C:\Installer\Acronis|Destination where the agent installer should be downloaded/saved to (used to start installation)|
|AgentType|   |can be either win, sql, hyperv or ad. If left empty it will auto detect one of the before mentioned, so just leave it empty.|
|Lang|de|Which language should the agent UI use?|
|Url|https://portal.ajani.info/|The full URL for your Acronis tenant (plugging Ajani right here)|
|ApiClientId|02baa9be-f1a2-4524-a8cb-0cd75c9acb61|API client ID|
|ApiClientSecret|mzrop4shdxil3ud4lvvdcn5l4acqtafufi4juudqabfhxga756pm|API client secret|

![Example in Riverbird](/Img/Riverbird%20Script%20Parameter%20Config.jpg)

## Step 4
Rollout the script as a job.

![Example in Riverbird](/Img/Riverbird%20Job%20Config.jpg)

## Step 5
Enjoy!