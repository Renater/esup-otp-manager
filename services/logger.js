const winston = require('winston');
const path = require('node:path');
const properties = require(__dirname + '/../properties/properties');

const logger = winston.createLogger({
    level: properties.esup.logs.level || 'info',
    format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        winston.format.printf(options => {
            return `${options.timestamp} ${options.level.toUpperCase()} ${undefined !== options.message ? options.message : ''}` +
                (options.meta && Object.keys(options.meta).length ? `\n\t${JSON.stringify(options.meta)}` : '');
        })
    ),
});

const transports = properties.esup.logs.transports;

if (transports === undefined || transports.length == 0) {
    // default: single console transport
    logger.add(new winston.transports.Console());
} else {
    for (const transport of transports) {
	switch (transport.type) {
	    case 'console':
		logger.add(new winston.transports.Console(transport.options));
		break;
	    case 'file':
		logger.add(new winston.transports.File(transport.options));
		break;
	    case 'http':
		logger.add(new winston.transports.Http(transport.options));
		break;
	    case 'stream':
		logger.add(new winston.transports.Stream(transport.options));
		break;
	    default:
		throw new Error('invalid transport type: ' + transport.type);
	}
    }
}

exports.logger = logger;
