export type MessageType = 'message' | 'sign' | 'signature';

export interface Message {
    type: MessageType;
    data: any;
}

export type MessageHandler = (message: Message) => void

export class MessageService {
    private static instance: MessageService;

    private handlers: Record<MessageType, MessageHandler[]> = {
        message: [],
        sign: [],
        signature: [],
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

    public registerHandler(type: MessageType, handler: MessageHandler) {
        this.handlers[type].push(handler);
    }

    public sendMessage(message: Message) {
        // @ts-ignore
        if (!!window.ReactNativeWebView) {
            // @ts-ignore
            window.ReactNativeWebView.postMessage(JSON.stringify(message));
        } else if (window.top) {
            window.top.postMessage(JSON.stringify(message), 'https://localdev.dimo.org:3008');
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
        if (!message.type || !['message', 'sign','signature'].includes(message.type)) {
            return;
        }

        for (const handler of this.handlers[message.type]) {
            handler(message);
        }
    }
}
