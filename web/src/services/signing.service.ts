import {Message, MessageService} from "@services/message.service.ts";

export interface SignatureMessageData {
    signature: `0x${string}`,
    sacd?: any,
}

type ResolveFn = (value: SignatureMessageData | PromiseLike<SignatureMessageData>) => void

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

    public async signMintTypedData(typedData: any) {
        if (!this.messageService) {
            console.error('No MessageService registered');
            return Promise.reject('No MessageService registered');
        }

        if (!!this.waitForSignatureTimeout) {
            console.warn('Signature is already scheduled');
            return Promise.reject('Signature is already scheduled');
        }

        this.messageService.sendMessage({type: 'sign-mint', data: {typedData}});
        // artificially waits until user completes operation by listening to a message coming from host with below onMessage, which is registered in useMessageService
        return new Promise<SignatureMessageData>((resolve, reject) => {
            this.waitForSignatureTimeout = setTimeout(() => {
                return reject('Signature timed out')
            }, 120_000);

            this.waitForSignatureResolve = (value: SignatureMessageData | PromiseLike<SignatureMessageData>)=> {
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
            this.waitForSignatureResolve(message.data as SignatureMessageData);
            this.waitForSignatureResolve = undefined;
        }
    }
}
