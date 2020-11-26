const fs = require('fs')
const {log} = console
const data = require('./testHeadersBench.json')
const FILE_NAME = './testHeaderHashes.json'

const main = async () => {
    fs.writeFileSync(FILE_NAME, JSON.stringify(data.calculateBlockHash))
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });
