import TransportU2F from "@ledgerhq/hw-transport-u2f";
import LedgerEth from "@ledgerhq/hw-app-eth";

//初始化即可开始监听
class LedgerBridge {
    constructor() {
        this.listenFromIframe();
        console.log("window start---->", window);
    }

    listenFromIframe() {
        window.addEventListener(
            "message",
            async eve => {
                if (eve && eve.data && eve.data.target === "LEDGER-IFRAME") {
                    const {action, params} = eve.data;
                    console.log(
                        "ev from ledger-iframe",
                        eve,
                        eve.origin,
                        eve.originalEvent
                    );

                    const actionReply = `${action}-reply`;
                    const actionMap = {
                        "ledger-unlock":
                            () => this.unlock(actionReply, params.hdPath),
                        "ledger-getAddress":
                            () => this.getAddress(actionReply),
                        "ledger-getAppConfiguration":
                            () => this.getAppConfiguration(actionReply),
                        "ledger-sign-transaction":
                            () => this.signTransaction(
                                actionReply,
                                params.hdPath,
                                params.serializedTxHex
                            ),
                        "ledger-sign-personal-message":
                            () => this.signPersonalMessage(
                                actionReply,
                                params.hdPath,
                                params.message
                            ),
                        undefined:
                            () => {}
                    };
                    actionMap[action]();
                } else {
                    console.log("not ledger-iframe", eve);
                }
            },
            false
        );
    }

    sendMessageToExtension(msg) {
        window.parent.postMessage(msg, "*");
    }

    async initApp() {
        try {
            this.transport = await TransportU2F.create();
            this.app = new LedgerEth(this.transport);
        } catch (err) {
            console.log("LEDGER:::CREATE APP ERROR", err);
        }
    }

    cleanUp() {
        this.app = null;
        this.transport.close();
    };

    async unlock(actionReply, hdPath) {
        try {
            await this.initApp();
            const res = await this.app.getAddress(hdPath, false, true);
            this.sendMessageToExtension({
                action: actionReply,
                success: true,
                payload: res
            });
        } catch (err) {
            const e = this.ledgerErrToMessage(err);
            this.sendMessageToExtension({
                action: actionReply,
                success: false,
                payload: {error: e.toString()}
            });
        } finally {
            this.cleanUp();
        }
    };

    async getAddress(actionReply) {
        try {
            await this.initApp();
            const {address} = (await this.app.getAddress())||{};
            this.sendMessageToExtension({
                action: actionReply,
                success: true,
                payload: address
            });
        } catch (err) {
            const e = this.ledgerErrToMessage(err);
            this.sendMessageToExtension({
                action: actionReply,
                success: false,
                payload: {error: e.toString()}
            });
        } finally {
            this.cleanUp();
        }
    };

    async getAppConfiguration(actionReply) {
        try {
            await this.initApp();
            const res = await this.app.getAppConfiguration();
            this.sendMessageToExtension({
                action: actionReply,
                success: true,
                payload: res
            });
        } catch (err) {
            const e = this.ledgerErrToMessage(err);
            this.sendMessageToExtension({
                action: actionReply,
                success: false,
                payload: {error: e.toString()}
            });
        } finally {
            this.cleanUp();
        }
    };

    async signTransaction(actionReply, hdPath, serializedTxHex) {
        try {
            await this.initApp();
            const res = await this.app.signTransaction(hdPath, serializedTxHex);
            this.sendMessageToExtension({
                action: actionReply,
                success: true,
                payload: res
            });
        } catch (err) {
            const e = this.ledgerErrToMessage(err);
            this.sendMessageToExtension({
                action: actionReply,
                success: false,
                payload: {error: e.toString()}
            });
        } finally {
            this.cleanUp();
        }
    };

    async signPersonalMessage(actionReply, hdPath, message) {
        try {
            await this.initApp();
            const res = await this.app.signPersonalMessage(hdPath, message);
            this.sendMessageToExtension({
                action: actionReply,
                success: true,
                payload: res
            });
        } catch (err) {
            const err_msg = this.ledgerErrToMessage(err);
            this.sendMessageToExtension({
                action: actionReply,
                success: false,
                payload: {error: err_msg.toString()}
            });
        } finally {
            this.cleanUp();
        }
    };

    ledgerErrToMessage(err) {
        const isU2FError = err => !!err && !!err.metaData;
        const isStringError = err => typeof err === "string";
        const isErrorWithId = err =>
            err.hasOwnProperty("id") && err.hasOwnProperty("message");

        // https://developers.yubico.com/U2F/Libraries/Client_error_codes.html
        if (isU2FError(err)) {
            return err.metaData.code === 5 ? "LEDGER_TIMEOUT" : err.metaData.type;
        }

        if (isStringError(err)) {
            // Wrong app logged into
            if (err.includes("6804")) {
                return "LEDGER_WRONG_APP";
            }
            // Ledger locked
            if (err.includes("6801")) {
                return "LEDGER_LOCKED";
            }

            return err;
        }

        if (isErrorWithId(err)) {
            // Browser doesn't support U2F
            if (err.message.includes("U2F not supported")) {
                return "U2F_NOT_SUPPORTED";
            }
        }

        // Other
        return err.toString();
    }
}

export default LedgerBridge;
