import {Message, MessageService} from "@services/message.service.ts";

type ResolveFn = (value: `0x${string}` | PromiseLike<`0x${string}`>) => void

export class SigningService {
    private static instance: SigningService;
    private messageService?: MessageService;
    private waitForSignatureTimeout?: NodeJS.Timeout;
    private waitForSignatureResolve?: ResolveFn;

    private constructor() {}

    public static getInstance(): SigningService {
        if (!SigningService.instance) {
            SigningService.instance = new SigningService();
        }
        return SigningService.instance;
    }

    public useMessageService(messageService: MessageService) {
        this.messageService = messageService;
        this.messageService.registerHandler('signature', this.onMessage.bind(this));
    }

    public async signTypedData(typedData: any) {
        if (!this.messageService) {
            console.error('No MessageService registered');
            return Promise.reject('No MessageService registered');
        }

        if (!!this.waitForSignatureTimeout) {
            console.warn('Signature is already scheduled');
            return Promise.reject('Signature is already scheduled');
        }

        this.messageService.sendMessage({type: 'sign', data: {typedData}});
        return new Promise<`0x${string}`>((resolve, reject) => {
            this.waitForSignatureTimeout = setTimeout(() => {
                return reject('Signature timed out')
            }, 120_000);

            this.waitForSignatureResolve = (value: `0x${string}` | PromiseLike<`0x${string}`>)=> {
                clearTimeout(this.waitForSignatureTimeout);
                this.waitForSignatureTimeout = undefined;
                this.waitForSignatureResolve = undefined;
                resolve(value);
            };
        })

    }

    private onMessage(message: Message) {
        console.debug('SigningService.onMessage', message)

        if (!!this.waitForSignatureResolve) {
            this.waitForSignatureResolve(message.data as `0x${string}`);
            this.waitForSignatureResolve = undefined;
        }
    }
}
