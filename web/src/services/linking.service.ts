import {Message, MessageService} from "@services/message.service.ts";

type ResolveFn = (value: OpenMessageData | PromiseLike<OpenMessageData>) => void

export interface OpenMessageData {
    url: string,
}

export class LinkingService {
    private static instance: LinkingService;
    private messageService?: MessageService;
    private waitForOpenTimeout?: NodeJS.Timeout;
    private waitForOpenResolve?: ResolveFn;

    private constructor() {}

    public static getInstance(): LinkingService {
        if (!LinkingService.instance) {
            LinkingService.instance = new LinkingService();
        }
        return LinkingService.instance;
    }

    public useMessageService(messageService: MessageService) {
        this.messageService = messageService;
        this.messageService.registerHandler('open', this.onMessage.bind(this));
    }

    public async openLink(url: string) {
        if (!this.messageService) {
            console.error('No MessageService registered');
            return Promise.reject('No MessageService registered');
        }

        if (!!this.waitForOpenTimeout) {
            console.warn('Link opening is already scheduled');
            return Promise.reject('Link opening is already scheduled');
        }

        this.messageService.sendMessage({type: 'open', data: {url}});
        return new Promise<OpenMessageData>((resolve, reject) => {
            this.waitForOpenTimeout = setTimeout(() => {
                return reject('Link opening timed out')
            }, 120_000);

            this.waitForOpenResolve = (value: OpenMessageData | PromiseLike<OpenMessageData>)=> {
                clearTimeout(this.waitForOpenTimeout);
                this.waitForOpenTimeout = undefined;
                this.waitForOpenResolve = undefined;
                resolve(value);
            };
        })
    }

    private onMessage(message: Message) {
        console.debug('SigningService.onMessage', message)

        if (!!this.waitForOpenResolve) {
            this.waitForOpenResolve(message.data as OpenMessageData);
            this.waitForOpenResolve = undefined;
        }
    }
}
