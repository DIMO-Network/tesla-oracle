import {LitElement} from 'lit'
import { property, state} from "lit/decorators.js";
import {ApiService} from "@services/api-service.ts";
import {SigningService} from "@services/signing.service.ts";
import qs from 'qs';
import {range} from "lodash";
import {delay} from "@utils/utils";

// verify's status detail for a VIN an earlier attempt already minted (see the backend's DetailsReadyToFinalize)
const READY_TO_FINALIZE = "Ready to finalize";

// A mint can take minutes: the worker waits up to 240s for its receipt, after
// any mints queued ahead of it. Poll for about 6 minutes.
const MINT_STATUS_POLL_INTERVAL_MS = 5000;
const MINT_STATUS_POLLS = 72;

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

// base class for other elements that will need to do onboarding operations, mostly copied from fleet-onboarding
export class BaseOnboardingElement extends LitElement {

    @property({attribute: false})
    protected processing: boolean;

    @property({attribute: false})
    protected processingMessage: string;

    @property({attribute: false})
    protected onboardResult: VinOnboardingStatus[];

    @state() sessionExpiresIn: number = 0;

    // why the last onboarding attempt failed; children render it
    @state() protected failureMessage: string = "";

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

    displayFailure(alertText: string) {
        this.processing = false;
        this.processingMessage = "";
        this.failureMessage = alertText;
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

    // returns why verification failed (null when every VIN passed), and whether every
    // VIN was already minted by an earlier attempt and only needs finalizing
    async verifyVehicles(vehicles: VehicleOnboardingData[]): Promise<{error: string | null, readyToFinalize: boolean}> {
        const payload = {
            vins: vehicles
        }

        const verificationStatus = await this.api.callApi<VinsOnboardingResult>('POST', '/v1/vehicle/verify', payload, true);
        if (!verificationStatus.success || !verificationStatus.data) {
            return {error: verificationStatus.error || "unknown error", readyToFinalize: false};
        }

        for (const vinStatus of verificationStatus.data.statuses) {
            if (vinStatus.status != "Success") {
                return {error: vinStatus.details || vinStatus.status, readyToFinalize: false};
            }
        }

        const statuses = verificationStatus.data.statuses;
        const readyToFinalize = statuses.length > 0 && statuses.every((s) => s.details === READY_TO_FINALIZE);
        return {error: null, readyToFinalize};
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
                // blocks until the operation completes by the user
                const signatureData = await this.signingService.signMintTypedData(d.typedData);

                if (!signatureData) {
                    continue
                }

                result.push({
                    ...d,
                    signature: signatureData.signature,
                    sacd: signatureData.sacd, // this is provided from the mobile app, or whatever signer is wrapping
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
        // submit the river job
        const mintResponse = await this.api.callApi('POST', '/v1/vehicle/mint', payload, true);
        if (!mintResponse.success || !mintResponse.data) {
            return false;
        }

        let success = true
        for (const attempt of range(MINT_STATUS_POLLS)) {
            success = true
            const query = qs.stringify({vins: mintingData.map(m => m.vin).join(',')}, {arrayFormat: 'comma'});
            // poll for the river job status, looking for Success
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

            if (attempt < MINT_STATUS_POLLS - 1) {
                await delay(MINT_STATUS_POLL_INTERVAL_MS);
            }
        }

        return success;
    }

    async finalize(vins: string[]) {
        return await this.api.callApi<FinalizeResponse>('POST', '/v1/vehicle/finalize', {vins}, true);
    }

    // this does the minting of vehicle and synthetic. borrowed from fleet web app
    async onboardVINs(vehicles: VehicleOnboardingData[]): Promise<FinalizeResponse | null> {
        this.failureMessage = "";
        // check vin validity
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
        // calls backend to make sure vehicle meets conditions. if a vehicle token id was passed in, verifies various things and updates record.
        const verification = await this.verifyVehicles(vehicles);
        if (verification.error) {
            this.displayFailure(`Failed to verify vehicles: ${verification.error}`);
            return null;
        }
        const vins = vehicles.map((v) => v.vin);
        // an earlier attempt already minted every VIN but never finalized: skip straight to finalize
        if (!verification.readyToFinalize) {
            // get the typed data to be signed.
            const mintData = await this.getMintingData(vins);
            if (mintData.length === 0) {
                this.displayFailure("Failed to fetch minting data");
                return null
            }
            // web3 operation to sign the passed in data, but signing is not done by the browser but instead by the host eg. mobile app
            const signedMintData = await this.signMintingData(mintData);
            // this step actually does the minting. Can do both Vehicle and Synthetic. Submits a River Job.
            const minted = await this.submitMintingData(signedMintData);

            if (!minted) {
                this.displayFailure("Failed to onboard at least one VIN");
                return null;
            }
        }
        // unique step for tesla. Creates record in the main oracle table, synthetic devices, and then deletes the onboarding record: Migrates the data.
        const finalized = await this.finalize(vins);
        if (!finalized.success || !finalized.data) {
            this.displayFailure(`Failed to finalize onboarding: ${finalized.error || "unknown error"}`);
            return null;
        }

        return finalized.data;
    }
}
