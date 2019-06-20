var EllipticCurve = artifacts.require("EllipticCurve");
var ECRecovery = artifacts.require("ECRecovery");


var BankAccounts = artifacts.require("BankAccounts");
var ECCLibrary = artifacts.require("ECC");

module.exports = function(deployer) {

    deployer.deploy(EllipticCurve);
    deployer.link(EllipticCurve, ECCLibrary)

    deployer.deploy(ECRecovery);
    deployer.link(ECRecovery, ECCLibrary);

    deployer.deploy(ECCLibrary);

    deployer.link(ECCLibrary, BankAccounts);
    deployer.deploy(BankAccounts, 0);
}
