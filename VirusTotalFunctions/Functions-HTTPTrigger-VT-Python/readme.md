This function accepts a inbound HTTP post/get request to your Azure Function. It will perform an API lookup on the indicator of your choice and if 5 or more determinations in VirusTotal are found, it will return the response from the API in the message body. 
Currently only accepts: IP, md5, sha1, sha256. 

Example post request can be seen here:
Body format:
{
    "IOC": ["d0d626deb3f9484e649294a8dfa814c5568f846d5aa02d4cdad5d041a29d5600"]
}


![image](https://user-images.githubusercontent.com/14184955/158974151-5273c1e2-69e5-4fcb-801c-60985fc083e0.png)
