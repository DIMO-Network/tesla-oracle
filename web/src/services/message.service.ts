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
        window.addEventListener('message', this.onMessage.bind(this));
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
        if (!!window.ReactNativeWebView) {
            window.ReactNativeWebView.postMessage(message);
        } else {
            window.top.postMessage(message, 'https://localdev.dimo.org:3008');
        }
    }

    private onMessage(event: MessageEvent) {
        if (!(['https://localdev.dimo.org:3008'].includes(event.origin))) {
            return;
        }

        const message = event.data as Message;
        if (!message.type || !['message', 'sign','signature'].includes(message.type)) {
            return;
        }

        for (const handler of this.handlers[message.type]) {
            console.debug('Handling message', message)
            handler(message);
        }
    }
}
