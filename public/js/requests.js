function signupRequest(name, email, password, phone, address) {
    return request(
        '/api/v1/auth/signup', 'POST',
        { name, email, password, phone, address, },
    );
}

function loginRequest(email, password) {
    return request(
        '/api/v1/auth/login', 'POST',
        { email, password, },
    );
}

function getMyDataRequest() {
    const authorization = sessionStorage.getItem('authorization');
    return request(
        '/api/v1/users/me', 'GET',
        {}, { authorization },
    );
}

async function request(url, method, body={}, headers={}) {
    headers['Content-Type'] = 'application/json';
    return fetch(url, {
        method,
        headers,
        body: method == 'GET' ? undefined : JSON.stringify(body),
    }).then(response => {
        return Promise.all([response.status, response.json()]);
    }).then(([status, body]) => {
        return { status, body, };
    }).catch((e) => {
        return { status: -1, body: { error: 'Algo salió mal', }, };
    });
}
