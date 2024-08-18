const axios = require('axios');

function testAxios() {
    const client = axios.create();
    console.log('Axios Client:', client);
}

testAxios();
