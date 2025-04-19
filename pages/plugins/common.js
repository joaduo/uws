
async function getJSON(endpoint){
    let url = host + '/' + endpoint;
    let headers =  {
        'Content-Type': 'application/json'
    };
    let request = {
        method:"GET",
        headers
    };
    let page = await fetch(url,request);
    let json = await page.json();
    console.log(json);
    return json
}

async function postJSON(endpoint, payload, auth_token){
    let url = host + '/' + endpoint;
    let data = {"auth_token": auth_token, "payload":payload}
    let headers =  {
        'Content-Type': 'application/json'
    };
    let request = {
        method:"POST",
        body:JSON.stringify(data),
        headers
    };
    let page = await fetch(url,request);
    let json = await page.json();
    console.log(json);
    return json
}

async function getAPIText(endpoint){
    let url = host + '/' + endpoint;
    let headers =  {
        'Content-type': 'text/plain'
    };
    let request = {
        method:'GET',
        headers
    };
    let page = await fetch(url, request);
    return await page.text();
}
 