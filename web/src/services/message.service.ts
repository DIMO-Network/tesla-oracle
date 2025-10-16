// types of messages to be sent to mobile app host. It needs to know how to interpret these. sign-mint includes SACD.
// Some of these are sent from us to the host, others are received from the host. Any changes here must be done in mobile app too.
export type MessageType = 'message' | 'sign' | 'sign-mint' | 'signature' | 'onboarded' | 'open';

export interface Message {
    type: MessageType;
    data: any;
}

export type MessageHandler = (message: Message) => void

// handles communication between mobile Host and the web UI
export class MessageService {
    private static instance: MessageService;

    private handlers: Record<MessageType, MessageHandler[]> = {
        message: [],
        sign: [],
        'sign-mint': [],
        signature: [],
        onboarded: [],
        open: [],
    };

    private constructor() {
        // iOS uses window
        window.addEventListener('message', this.onMessage.bind(this));
        // @ts-ignore Android uses document
        document.addEventListener('message', this.onMessage.bind(this));
    }

    public static getInstance(): MessageService {
        if (!MessageService.instance) {
            MessageService.instance = new MessageService();
        }
        return MessageService.instance;
    }

    // this can be used to register your own listeners
    public registerHandler(type: MessageType, handler: MessageHandler) {
        this.handlers[type].push(handler);
    }

    public sendMessage(message: Message) {
        console.log('[MessageService Debug] sendMessage called', {
            messageType: message.type,
            hasReactNativeWebView: !!(window as any).ReactNativeWebView,
            hasWindowTop: !!window.top
        });

        // @ts-ignore
        if (!!window.ReactNativeWebView) {
            console.log('[MessageService Debug] Sending via ReactNativeWebView.postMessage');
            // @ts-ignore
            // React Native WebView uses its own postMessage API that doesn't require targetOrigin
            window.ReactNativeWebView.postMessage(JSON.stringify(message));
            console.log('[MessageService Debug] ReactNativeWebView.postMessage called');
        } else if (window.top && window.top !== window) {
            console.log('[MessageService Debug] Sending via window.top.postMessage');
            // For browser iframe communication, specify targetOrigin for security
            // Use '*' since we don't know the parent origin, but this should only be used in development
            window.top.postMessage(JSON.stringify(message), '*');
            console.log('[MessageService Debug] window.top.postMessage called');
        } else {
            console.error('[MessageService Debug] No available postMessage target!');
        }
    }

    private onMessage(event: MessageEvent) {
        console.debug('MessageService.onMessage', event)

        // @ts-ignore
        if (!!window.ReactNativeWebView) {
            // TODO: figure out a way to validate if the message was sent from the mobile app
        } else {
            // TODO: for the browser validate event origin (browser plugins may send messages too)
        }

        if (typeof(event.data) != "string") {
            return;
        }

        const message = JSON.parse(event.data) as Message;
        if (!message.type || !['message', 'signature', 'open'].includes(message.type)) {
            return;
        }

        for (const handler of this.handlers[message.type]) {
            handler(message);
        }
    }
}
