import properties from '../properties/properties.js';

const passwords = new Map();

async function getTenantByName(name) {
    const response = await fetch(properties.esup.api_url + '/admin/tenants', {headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + properties.esup.admin_password
    }});
    const data = await response.json();
    return data.find(item => item.name === name);
}

async function getTenantById(id) {
    const response = await fetch(properties.esup.api_url + '/admin/tenant/' + id, {headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + properties.esup.admin_password
    }});
    return await response.json();
}

export async function getApiPassword(name) {
    if (!passwords.has(name)) {
	const apiTenant = await getTenantByName(name);

	if (apiTenant) {
	    const tenant = await getTenantById(apiTenant.id);
	    passwords.set(name, tenant.api_password);
	}
    }

    return passwords.get(name);
}
