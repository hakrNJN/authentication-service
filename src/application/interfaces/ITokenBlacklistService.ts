export interface ITokenBlacklistService {
    addToBlacklist(tokenId: string, expirationTime: number): Promise<void>;
    isBlacklisted(tokenId: string): Promise<boolean>;
    disconnect(): Promise<void>;
}
