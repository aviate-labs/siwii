interface AuthReadyMessage {
    kind: "authorize-ready";
}

interface AuthResponseSuccess {
    kind: "authorize-client-success";
    delegations: {
        delegation: {
            pubkey: Uint8Array;
            expiration: bigint;
        };
        signature: Uint8Array;
    }[];
    userPublicKey: Uint8Array;
    authnMethod: "passkey" | "pin" | "recovery";
}

async function login(
    sessionPublicKey: Uint8Array,
): Promise<AuthResponseSuccess> {
    console.log(sessionPublicKey);

    const u = new URL("https://identity.ic0.app/");
    u.hash = "#authorize";
    const popup = window.open(u, "ii-window", "width=400,height=400");

    while (true) {
        const readyMessage = await new Promise<MessageEvent>((resolve) => {
            const listener = (ev: MessageEvent) => {
                window.removeEventListener("message", listener);
                resolve(ev);
            };
            window.addEventListener("message", listener);
        });

        const readyMessageData = readyMessage.data as AuthReadyMessage;
        if (readyMessageData.kind !== "authorize-ready") {
            console.warn("Unexpected message", readyMessage.data);
        } else {
            console.log("Received ready message.")
            break;
        }
    }

    while (true) {
        popup.postMessage({
            kind: "authorize-client",
            sessionPublicKey,
        }, u.origin);

        const authorizeMessage = await new Promise<MessageEvent>((resolve) => {
            const listener = (ev: MessageEvent) => {
                window.removeEventListener("message", listener);
                resolve(ev);
            };
            window.addEventListener("message", listener);
        });

        const authorizeMessageData = authorizeMessage.data as AuthResponseSuccess;
        if (authorizeMessageData.kind !== "authorize-client-success") {
            console.warn("Unexpected message", authorizeMessage.data);
        } else {
            console.log("Received authorize message.")
            popup.close();
            console.log(authorizeMessageData);
            return authorizeMessageData;
        }
    }
}

window.onload = async () => {
    const loginButton = document.getElementById("login")!;
    loginButton.addEventListener("click", async () => {
        const challengeResp = await fetch("http://localhost:8123/challenge");
        const {challenge} = await challengeResp.json();
        const sessionPublicKey = new Uint8Array(Buffer.from(challenge, "base64"));

        const delegation = await login(sessionPublicKey);
        const resp = await fetch("http://localhost:8123/auth", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                challenge,
                delegation,
            }, (_, v) => {
                if (typeof v === "bigint") {
                    // We need to expiration date to be hex string.
                    return (v as BigInt).toString(16);
                }
                if (v instanceof Uint8Array) {
                    // We need the keys to be hex strings.
                    return (v as Uint8Array).reduce((str, byte) => str + byte.toString(16).padStart(2, "0"), "");
                }
                return v;
            }),
        });
    })
}