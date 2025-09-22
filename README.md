# esup-otp-manager

Manager for the esup-otp-api. Allow users to edit their preferences and admins to administrate ;)

## Version

2.0 **Require `npm install`**

## Requirements

- [esup-otp-api](https://github.com/EsupPortail/esup-otp-api)

## Installation

```sh
# Download esup-otp-manager
git clone https://github.com/EsupPortail/esup-otp-manager.git
# Install required libraries
npm install
# change the fields values in properties/esup.json to your installation, some explanations are in `#how_to` attributes
# Start server
npm start
```

### Behind Apache

- https

```apache
RequestHeader set X-Forwarded-Proto https
RequestHeader set X-Forwarded-Port 443

RewriteEngine On

RewriteCond %{QUERY_STRING} transport=websocket [NC]
RewriteRule /(.*) ws://127.0.0.1:4000/$1 [P]


<Location />
ProxyPass http://127.0.0.1:4000/ retry=1
ProxyPassReverse http://127.0.0.1:4000/
</Location>
```

### Systemd

```ini
[Unit]
Description=esup-otp-manager nodejs app
Documentation=https://github.com/EsupPortail/esup-otp-manager
After=network.target

[Service]
Type=simple
User=esup
WorkingDirectory=/opt/esup-otp-manager
ExecStart=/usr/bin/node run
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

## License

Please see the file called `LICENSE`.
