import {LitElement} from 'lit'
import { property, state} from "lit/decorators.js";
import {ApiService} from "@services/api-service.ts";
import {SigningService} from "@services/signing.service.ts";
import qs from 'qs';
import {range} from "lodash";
import {delay} from "@utils/utils";

interface VehicleOnboardingData {
    vin: string;
    vehicleTokenId?: number;
}

interface VinOnboardingStatus {
    vin: string;
    status: string;
    details: string;
}

interface VinsOnboardingResult {
    statuses: VinOnboardingStatus[];
}

interface VinMintData {
    vin: string;
    typedData: any;
    signature?: `0x${string}`;
    sacd?: any;
}

interface VinsMintDataResult {
    vinMintingData: VinMintData[];
}

export interface SacdInput {
    grantee: `0x${string}`;
    permissions: BigInt;
    expiration: BigInt;
    source: string
}

export interface VinUserOperationData {
    vin: string;
    userOperation: Object;
    hash: string;
    signature?: string;
}

export interface VinsDisconnectDataResult {
    vinDisconnectData: VinUserOperationData[];
}

export interface VinsDeleteDataResult {
    vinDeleteData: VinUserOperationData[];
}

export interface VinStatus {
    vin: string;
    status: string;
    details: string;
}

export interface VinsStatusResult {
    statuses: VinStatus[];
}

export interface OnboardedVehicle {
    vin: string,
    vehicleTokenId: number,
    syntheticTokenId: number,
}

export interface FinalizeResponse {
    vehicles: OnboardedVehicle[]
}

export class BaseOnboardingElement extends LitElement {

    @property({attribute: false})
    protected processing: boolean;

    @property({attribute: false})
    protected processingMessage: string;

    @property({attribute: false})
    protected onboardResult: VinOnboardingStatus[];

    @state() sessionExpiresIn: number = 0;

    protected api: ApiService;
    protected signingService: SigningService;

    constructor() {
        super();
        this.processing = false;
        this.processingMessage = "";
        this.api = ApiService.getInstance();
        this.signingService = SigningService.getInstance();
        this.onboardResult = []
    }

    // this method should be overridden by children
    displayFailure(_alertText: string) {
        this.processing = false;
        this.processingMessage = "";
    }

    updateResult(result : VinsOnboardingResult) {
        const statusesByVin: Record<string, VinOnboardingStatus> = {}
        for (const item of result.statuses) {
            statusesByVin[item.vin] = item
        }

        const newResult: VinOnboardingStatus[] = [];

        for (const item of this.onboardResult) {
            newResult.push({
                vin: item.vin,
                status: statusesByVin[item.vin]?.status || "Unknown",
                details: statusesByVin[item.vin]?.details || "Unknown"
            })
        }

        this.onboardResult = newResult
    }

    async verifyVehicles(vehicles: VehicleOnboardingData[]) {
        const payload = {
            vins: vehicles
        }

        const verificationStatus = await this.api.callApi<VinsOnboardingResult>('POST', '/v1/vehicle/verify', payload, true);
        if (!verificationStatus.success || !verificationStatus.data) {
            return false;
        }

        for (const vinStatus of verificationStatus.data.statuses) {
            if (vinStatus.status != "Success") {
                return false;
            }
        }

        return true;
    }

    async getMintingData(vins: string[]) {
        const query = qs.stringify({vins: vins.join(',')}, {arrayFormat: 'comma'});
        const mintData = await this.api.callApi<VinsMintDataResult>('GET', `/v1/vehicle/mint?${query}`, null, true);
        if (!mintData.success || !mintData.data) {
            return [];
        }

        return mintData.data.vinMintingData;
    }

    async signMintingData(mintingData: VinMintData[]) {
        const result: VinMintData[] = [];
        for (const d of mintingData) {
            if (d.typedData) {
                const signatureData = await this.signingService.signMintTypedData(d.typedData);

                if (!signatureData) {
                    continue
                }

                result.push({
                    ...d,
                    signature: signatureData.signature,
                    sacd: signatureData.sacd,
                })
            } else {
                result.push(d)
            }
        }

        return result;
    }

    async submitMintingData(mintingData: VinMintData[]) {
        const payload: {vinMintingData: VinMintData[]} = {
            vinMintingData: mintingData,
        }

        const mintResponse = await this.api.callApi('POST', '/v1/vehicle/mint', payload, true);
        if (!mintResponse.success || !mintResponse.data) {
            return false;
        }

        let success = true
        for (const attempt of range(30)) {
            success = true
            const query = qs.stringify({vins: mintingData.map(m => m.vin).join(',')}, {arrayFormat: 'comma'});
            const status = await this.api.callApi<VinsOnboardingResult>('GET', `/v1/vehicle/mint/status?${query}`, null, true);

            if (!status.success || !status.data) {
                return false;
            }

            for (const s of status.data.statuses) {
                if (s.status !== 'Success') {
                    success = false;
                    break;
                }
            }

            this.updateResult(status.data)

            if (success) {
                break;
            }

            if (attempt < 19) {
                await delay(5000);
            }
        }

        return success;
    }

    async finalize(vins: string[]) {
        return await this.api.callApi<FinalizeResponse>('POST', '/v1/vehicle/finalize', {vins}, true);
    }

    // this does the minting of vehicle and synthetic. borrowed from fleet web app
    async onboardVINs(vehicles: VehicleOnboardingData[]): Promise<FinalizeResponse | null> {
        let allVinsValid = true;
        for (const vehicle of vehicles) {
            const validVin = vehicle.vin.length === 17
            allVinsValid = allVinsValid && validVin
            this.onboardResult.push({
                vin: vehicle.vin,
                status: "Unknown",
                details: validVin ? "Valid VIN" : "Invalid VIN"
            })
        }

        if (!allVinsValid) {
            this.displayFailure("Some of the VINs are not valid");
            return null;
        }

        const verified = await this.verifyVehicles(vehicles);
        if (!verified) {
            this.displayFailure("Failed to verify vehicles");
            return null;
        }

        const vins = vehicles.map((v) => v.vin);
        const mintData = await this.getMintingData(vins);
        if (mintData.length === 0) {
            this.displayFailure("Failed to fetch minting data");
            return null
        }

        const signedMintData = await this.signMintingData(mintData);
        const minted = await this.submitMintingData(signedMintData);

        if (!minted) {
            this.displayFailure("Failed to onboard at least one VIN");
            return null;
        }

        const finalized = await this.finalize(vins);
        if (!finalized.success || !finalized.data) {
            return null;
        }

        return finalized.data;
    }
}
