interface ApiResponse<T> {
    success: boolean;
    data?: T;
    error?: string;
    status?: number;
}

export class ApiService {
    private static instance: ApiService;
    private readonly baseUrl: string;

    private constructor() {
        this.baseUrl = this.getBaseUrl();
    }

    public static getInstance(): ApiService {
        if (!ApiService.instance) {
            ApiService.instance = new ApiService();
        }
        return ApiService.instance;
    }

    private getBaseUrl(): string {
        // FIXME: get the proper non-local logic
        return ""//window.origin;
        // this was used for testing locally from mobile app.
        // return "https://192.168.50.215:8080"//window.origin;
    }

    private getAuthorizationHeader(auth: boolean): Record<string, string> {
        if (!auth) return {};
        const token = localStorage.getItem('token');
        return token ? {"Authorization": `Bearer ${token}`} : {};
    }

    private async processResponse(response: Response): Promise<any> {
        const contentType = response.headers.get("Content-Type");

        if (contentType && contentType.includes("application/json")) {
            return await response.json();
        } else {
            return await response.text();
        }
    }

    public async callApi<T>(
        method: 'GET' | 'POST',
        endpoint: string,
        requestBody: Record<string, any> | null = null,
        auth: boolean = false,
    ): Promise<ApiResponse<T>> {
        const body = requestBody ? JSON.stringify(requestBody) : null;

        const headers: Record<string, string> = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            ...this.getAuthorizationHeader(auth),
        };

        try {
            const response = await fetch(`${this.baseUrl}${endpoint}`, {method, headers, body});

            const result = await this.processResponse(response);

            if (!response.ok) {
                return {
                    success: false,
                    error: result.message || result || "HTTP error",
                    status: response.status,
                };
            }

            console.debug(`HTTP Success [${method} ${endpoint}]:`, result);
            return {
                success: true,
                data: result,
            };
        } catch (error: any) {
            console.error(`Error calling [${method}] ${endpoint}:`, error);
            return {
                success: false,
                error: error.message || "An unexpected error occurred",
            };
        }
    }
}
