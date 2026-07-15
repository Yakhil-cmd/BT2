import json
import os

from decouple import config

# todo: if scope_files is: 500 > 50, 300 > 30 , 100 > 10
MAX_REPO = 25
# todo: the path from https://github.com/Chia-Network/chia-blockchain-gui
SOURCE_REPO = "near/nearcore"
# todo: the name of the repository
REPO_NAME = "nearcore"
run_number = os.environ.get('GITHUB_RUN_NUMBER') or os.environ.get('CI_PIPELINE_IID', '0')


def get_cyclic_index(run_number, max_index=100):
    """Convert run number to a cyclic index between 1 and max_index"""
    return (int(run_number) - 1) % max_index + 1


def load_repository_urls():
    """Load repository URLs from repositories.json."""
    repo_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "repositories.json")
    if not os.path.exists(repo_file):
        return []

    try:
        with open(repo_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []

    if not isinstance(data, list):
        return []

    return [url for url in data if isinstance(url, str) and url.strip()]


if run_number == "0":
    BASE_URL = f"https://deepwiki.com/{SOURCE_REPO}"
else:
    repository_urls = load_repository_urls()
    if repository_urls:
        run_index = get_cyclic_index(run_number, len(repository_urls))
        BASE_URL = repository_urls[run_index - 1]
    else:
        BASE_URL = f"https://deepwiki.com/{SOURCE_REPO}"

scope_files = [
    "packages/api/src/Client.ts",
    "packages/api/src/Message.ts",
    "packages/api/src/services/Daemon.ts",
    "packages/api/src/services/DataLayer.ts",
    "packages/api/src/services/Events.ts",
    "packages/api/src/services/Farmer.ts",
    "packages/api/src/services/FullNode.ts",
    "packages/api/src/services/Harvester.ts",
    "packages/api/src/services/PlotterService.ts",
    "packages/api/src/services/Service.ts",
    "packages/api/src/services/WalletService.ts",
    "packages/api/src/utils/calculateRoyalties.ts",
    "packages/api/src/utils/normalizeHex.ts",
    "packages/api/src/utils/toBech32m.ts",
    "packages/api/src/utils/toCamelCase.ts",
    "packages/api/src/utils/toSafeNumber.ts",
    "packages/api/src/utils/toSnakeCase.ts",
    "packages/api/src/wallets/CAT.ts",
    "packages/api/src/wallets/DID.ts",
    "packages/api/src/wallets/DL.ts",
    "packages/api/src/wallets/NFT.ts",
    "packages/api/src/wallets/Pool.ts",
    "packages/api/src/wallets/RL.ts",
    "packages/api/src/wallets/VC.ts",
    "packages/api-react/src/api.ts",
    "packages/api-react/src/chiaLazyBaseQuery.ts",
    "packages/api-react/src/hooks/useCurrentFingerprintSettings.ts",
    "packages/api-react/src/hooks/useFingerprintSettings.ts",
    "packages/api-react/src/hooks/useGetLocalCatName.ts",
    "packages/api-react/src/hooks/useGetNFTWallets.ts",
    "packages/api-react/src/hooks/useLocalStorage.ts",
    "packages/api-react/src/hooks/useNFTCoinAdded.ts",
    "packages/api-react/src/hooks/useNFTCoinDIDSet.ts",
    "packages/api-react/src/hooks/useNFTCoinRemoved.ts",
    "packages/api-react/src/hooks/useNFTCoinUpdated.ts",
    "packages/api-react/src/hooks/usePrefs.ts",
    "packages/api-react/src/hooks/useService.ts",
    "packages/api-react/src/hooks/useServices.ts",
    "packages/api-react/src/hooks/useSubscribeToEvent.ts",
    "packages/api-react/src/hooks/useThrottleQuery.ts",
    "packages/api-react/src/hooks/useVCEvents.ts",
    "packages/api-react/src/services/client.ts",
    "packages/api-react/src/services/daemon.ts",
    "packages/api-react/src/services/dataLayer.ts",
    "packages/api-react/src/services/farmer.ts",
    "packages/api-react/src/services/fullNode.ts",
    "packages/api-react/src/services/harvester.ts",
    "packages/api-react/src/services/plotter.ts",
    "packages/api-react/src/services/wallet.ts",
    "packages/api-react/src/slices/api.ts",
    "packages/api-react/src/slices/walletRpcPreferences.ts",
    "packages/api-react/src/store.ts",
    "packages/api-react/src/utils/EventEmitter.ts",
    "packages/api-react/src/utils/onCacheEntryAddedInvalidate.ts",
    "packages/api-react/src/utils/reduxToolkitEndpointAbstractions.ts",
    "packages/api-react/src/utils/withAllowUnsynced.ts",
    "packages/core/src/components/AddressBookProvider/AddressBookProvider.tsx",
    "packages/core/src/components/Auth/AuthProvider.tsx",
    "packages/core/src/components/GuestRoute/GuestRoute.tsx",
    "packages/core/src/components/Link/Link.tsx",
    "packages/core/src/components/ModalDialogs/ModalDialogs.tsx",
    "packages/core/src/components/ModalDialogs/ModalDialogsContext.tsx",
    "packages/core/src/components/ModalDialogs/ModalDialogsProvider.tsx",
    "packages/core/src/components/Persist/Persist.tsx",
    "packages/core/src/components/PrivateRoute/PrivateRoute.tsx",
    "packages/core/src/components/SandboxedIframe/SandboxedIframe.tsx",
    "packages/core/src/hooks/useAddressBook.tsx",
    "packages/core/src/hooks/useAuth.ts",
    "packages/core/src/hooks/useGetLatestVersionFromWebsite.ts",
    "packages/core/src/hooks/useKeyringMigrationPrompt.tsx",
    "packages/core/src/hooks/useOpenDialog.ts",
    "packages/core/src/hooks/useOpenExternal.ts",
    "packages/core/src/hooks/usePersist.ts",
    "packages/core/src/hooks/usePersistState.ts",
    "packages/core/src/hooks/useShowError.tsx",
    "packages/core/src/hooks/useSkipMigration.ts",
    "packages/core/src/hooks/useValidateChangePassphraseParams.tsx",
    "packages/core/src/utils/catToMojo.ts",
    "packages/core/src/utils/chiaToMojo.ts",
    "packages/core/src/utils/getTransactionResult.ts",
    "packages/core/src/utils/getWalletSyncingStatus.ts",
    "packages/core/src/utils/isValidURL.ts",
    "packages/core/src/utils/mojoToCAT.ts",
    "packages/core/src/utils/mojoToChia.ts",
    "packages/core/src/utils/normalizePoolState.ts",
    "packages/core/src/utils/removeOldPoints.ts",
    "packages/core/src/utils/validAddress.ts",
    "packages/gui/src/index.tsx",
    "packages/gui/src/init-prefs.ts",
    "packages/gui/src/config/config.js",
    "packages/gui/src/config/env.ts",
    "packages/gui/src/components/addressbook/AddressBook.tsx",
    "packages/gui/src/components/addressbook/AddressBookSideBar.tsx",
    "packages/gui/src/components/addressbook/ContactAdd.tsx",
    "packages/gui/src/components/addressbook/ContactEdit.tsx",
    "packages/gui/src/components/addressbook/ContactSummary.tsx",
    "packages/gui/src/components/addressbook/MyContact.tsx",
    "packages/gui/src/components/app/App.tsx",
    "packages/gui/src/components/app/AppAutoLogin.tsx",
    "packages/gui/src/components/app/AppKeyringMigrator.tsx",
    "packages/gui/src/components/app/AppPassPrompt.tsx",
    "packages/gui/src/components/app/AppProviders.tsx",
    "packages/gui/src/components/app/AppRouter.tsx",
    "packages/gui/src/components/app/AppSelectMode.tsx",
    "packages/gui/src/components/app/AppState.tsx",
    "packages/gui/src/components/app/AppStatusHeader.tsx",
    "packages/gui/src/components/app/AppVersionWarning.tsx",
    "packages/gui/src/components/app/LogoutButton.tsx",
    "packages/gui/src/components/did/DIDProfileDropdown.tsx",
    "packages/gui/src/components/nfts/MultipleDownloadDialog.tsx",
    "packages/gui/src/components/nfts/NFTBurnDialog.tsx",
    "packages/gui/src/components/nfts/NFTContextualActions.tsx",
    "packages/gui/src/components/nfts/NFTDetails.tsx",
    "packages/gui/src/components/nfts/NFTMetadata.tsx",
    "packages/gui/src/components/nfts/NFTMoveToProfileDialog.tsx",
    "packages/gui/src/components/nfts/NFTPreview.tsx",
    "packages/gui/src/components/nfts/NFTPreviewDialog.tsx",
    "packages/gui/src/components/nfts/NFTTransferAction.tsx",
    "packages/gui/src/components/nfts/NFTTransferConfirmationDialog.tsx",
    "packages/gui/src/components/nfts/NFTs.tsx",
    "packages/gui/src/components/nfts/detail/NFTDetailV2.tsx",
    "packages/gui/src/components/nfts/gallery/NFTGallery.tsx",
    "packages/gui/src/components/nfts/provider/NFTProvider.tsx",
    "packages/gui/src/components/nfts/provider/NFTProviderContext.ts",
    "packages/gui/src/components/nfts/provider/hooks/useMetadataData.ts",
    "packages/gui/src/components/nfts/provider/hooks/useNFTData.ts",
    "packages/gui/src/components/nfts/provider/hooks/useNFTDataNachos.ts",
    "packages/gui/src/components/nfts/provider/hooks/useNFTDataOnDemand.ts",
    "packages/gui/src/components/nfts/utils.ts",
    "packages/gui/src/components/notification/Notification.tsx",
    "packages/gui/src/components/notification/NotificationAnnouncement.tsx",
    "packages/gui/src/components/notification/NotificationAnnouncementDialog.tsx",
    "packages/gui/src/components/notification/NotificationOffer.tsx",
    "packages/gui/src/components/notification/NotificationPreview.tsx",
    "packages/gui/src/components/notification/NotificationPreviewNFT.tsx",
    "packages/gui/src/components/notification/NotificationPreviewOffer.tsx",
    "packages/gui/src/components/notification/NotificationSendDialog.tsx",
    "packages/gui/src/components/notification/NotificationWrapper.tsx",
    "packages/gui/src/components/notification/NotificationsDropdown.tsx",
    "packages/gui/src/components/notification/NotificationsMenu.tsx",
    "packages/gui/src/components/notification/NotificationsProvider.tsx",
    "packages/gui/src/components/notification/utils.ts",
    "packages/gui/src/components/offers/ConfirmOfferCancellation.tsx",
    "packages/gui/src/components/offers/NFTOfferEditor.tsx",
    "packages/gui/src/components/offers/NFTOfferPreview.tsx",
    "packages/gui/src/components/offers/NFTOfferTokenSelector.tsx",
    "packages/gui/src/components/offers/NFTOfferViewer.tsx",
    "packages/gui/src/components/offers/OfferAcceptConfirmationDialog.tsx",
    "packages/gui/src/components/offers/OfferAsset.ts",
    "packages/gui/src/components/offers/OfferAssetSelector.tsx",
    "packages/gui/src/components/offers/OfferDataDialog.tsx",
    "packages/gui/src/components/offers/OfferDataEntryDialog.tsx",
    "packages/gui/src/components/offers/OfferEditor.tsx",
    "packages/gui/src/components/offers/OfferEditorConditionsPanel.tsx",
    "packages/gui/src/components/offers/OfferEditorRowData.ts",
    "packages/gui/src/components/offers/OfferExchangeRate.tsx",
    "packages/gui/src/components/offers/OfferImport.tsx",
    "packages/gui/src/components/offers/OfferManager.tsx",
    "packages/gui/src/components/offers/OfferRowData.tsx",
    "packages/gui/src/components/offers/OfferShareDialog.tsx",
    "packages/gui/src/components/offers/OfferState.ts",
    "packages/gui/src/components/offers/OfferSummary.tsx",
    "packages/gui/src/components/offers/OfferSummaryRow.tsx",
    "packages/gui/src/components/offers/utils.ts",
    "packages/gui/src/components/offers2/CancelOfferList.tsx",
    "packages/gui/src/components/offers2/CreateOfferBuilder.tsx",
    "packages/gui/src/components/offers2/DataLayerOfferViewer.tsx",
    "packages/gui/src/components/offers2/OfferBuilder.tsx",
    "packages/gui/src/components/offers2/OfferBuilderContext.tsx",
    "packages/gui/src/components/offers2/OfferBuilderExpirationSection.tsx",
    "packages/gui/src/components/offers2/OfferBuilderFeeSection.tsx",
    "packages/gui/src/components/offers2/OfferBuilderImport.tsx",
    "packages/gui/src/components/offers2/OfferBuilderNFT.tsx",
    "packages/gui/src/components/offers2/OfferBuilderNFTRoyalties.tsx",
    "packages/gui/src/components/offers2/OfferBuilderNFTSection.tsx",
    "packages/gui/src/components/offers2/OfferBuilderProvider.tsx",
    "packages/gui/src/components/offers2/OfferBuilderRoyaltyPayouts.tsx",
    "packages/gui/src/components/offers2/OfferBuilderToken.tsx",
    "packages/gui/src/components/offers2/OfferBuilderTokenSelector.tsx",
    "packages/gui/src/components/offers2/OfferBuilderTokensSection.tsx",
    "packages/gui/src/components/offers2/OfferBuilderViewer.tsx",
    "packages/gui/src/components/offers2/OfferBuilderViewerDialog.tsx",
    "packages/gui/src/components/offers2/OfferBuilderWalletAmount.tsx",
    "packages/gui/src/components/offers2/OfferBuilderWalletBalance.tsx",
    "packages/gui/src/components/offers2/OfferBuilderXCHSection.tsx",
    "packages/gui/src/components/offers2/OfferDetails.tsx",
    "packages/gui/src/components/offers2/OfferEditorCancelConflictingOffersDialog.tsx",
    "packages/gui/src/components/offers2/OfferIncomingTable.tsx",
    "packages/gui/src/components/offers2/OffersProvider.tsx",
    "packages/gui/src/components/offers2/utils/createDefaultValues.ts",
    "packages/gui/src/components/offers2/utils/defaultValues.ts",
    "packages/gui/src/components/plotNFT/PlotExternalNFTCard.tsx",
    "packages/gui/src/components/plotNFT/PlotNFTAbsorbRewards.tsx",
    "packages/gui/src/components/plotNFT/PlotNFTAdd.tsx",
    "packages/gui/src/components/plotNFT/PlotNFTCard.tsx",
    "packages/gui/src/components/plotNFT/PlotNFTChangePool.tsx",
    "packages/gui/src/components/plotNFT/PlotNFTExternalState.tsx",
    "packages/gui/src/components/plotNFT/PlotNFTGetPoolLoginLinkDialog.tsx",
    "packages/gui/src/components/plotNFT/PlotNFTPayoutInstructionsDialog.tsx",
    "packages/gui/src/components/plotNFT/select/PlotNFTSelectBase.tsx",
    "packages/gui/src/components/plotNFT/select/PlotNFTSelectPool.tsx",
    "packages/gui/src/components/pool/Pool.tsx",
    "packages/gui/src/components/pool/PoolAbsorbRewards.tsx",
    "packages/gui/src/components/pool/PoolJoin.tsx",
    "packages/gui/src/components/settings/ChangePassphrasePrompt.tsx",
    "packages/gui/src/components/settings/IdentitiesPanel.tsx",
    "packages/gui/src/components/settings/LimitCacheSize.tsx",
    "packages/gui/src/components/settings/ProfileAdd.tsx",
    "packages/gui/src/components/settings/ProfileView.tsx",
    "packages/gui/src/components/settings/RemovePassphrasePrompt.tsx",
    "packages/gui/src/components/settings/ResyncPrompt.tsx",
    "packages/gui/src/components/settings/SetPassphrasePrompt.tsx",
    "packages/gui/src/components/settings/Settings.tsx",
    "packages/gui/src/components/settings/SettingsAdvanced.tsx",
    "packages/gui/src/components/settings/SettingsCustody.tsx",
    "packages/gui/src/components/settings/SettingsCustodyAutoClaim.tsx",
    "packages/gui/src/components/settings/SettingsCustodyClawbackOutgoing.tsx",
    "packages/gui/src/components/settings/SettingsDataLayer.tsx",
    "packages/gui/src/components/settings/SettingsDerivationIndex.tsx",
    "packages/gui/src/components/settings/SettingsExpiringOffers.tsx",
    "packages/gui/src/components/settings/SettingsGeneral.tsx",
    "packages/gui/src/components/settings/SettingsHarvester.tsx",
    "packages/gui/src/components/settings/SettingsIntegration.tsx",
    "packages/gui/src/components/settings/SettingsNFT.tsx",
    "packages/gui/src/components/settings/SettingsNotifications.tsx",
    "packages/gui/src/components/settings/SettingsPanel.tsx",
    "packages/gui/src/components/settings/SettingsProfiles.tsx",
    "packages/gui/src/components/settings/SettingsStartup.tsx",
    "packages/gui/src/components/settings/SettingsVerifiableCredentials.tsx",
    "packages/gui/src/components/signVerify/SignMessage.tsx",
    "packages/gui/src/components/signVerify/SignMessageEntities.ts",
    "packages/gui/src/components/signVerify/SignMessageResultDialog.tsx",
    "packages/gui/src/components/signVerify/SignVerifyDialog.tsx",
    "packages/gui/src/components/signVerify/SigningEntityDID.tsx",
    "packages/gui/src/components/signVerify/SigningEntityNFT.tsx",
    "packages/gui/src/components/signVerify/SigningEntityWalletAddress.tsx",
    "packages/gui/src/components/signVerify/VerifyMessage.tsx",
    "packages/gui/src/components/signVerify/VerifyMessageImport.tsx",
    "packages/gui/src/components/vcs/VCCard.tsx",
    "packages/gui/src/components/vcs/VCDetail.tsx",
    "packages/gui/src/components/vcs/VCEditTitle.tsx",
    "packages/gui/src/components/vcs/VCGetTimestamp.tsx",
    "packages/gui/src/components/vcs/VCList.tsx",
    "packages/gui/src/components/vcs/VCRevokeDialog.tsx",
    "packages/gui/src/components/vcs/VCs.tsx",
    "packages/gui/src/components/walletConnect/WalletConnectAddConnectionDialog.tsx",
    "packages/gui/src/components/walletConnect/WalletConnectConnections.tsx",
    "packages/gui/src/components/walletConnect/WalletConnectDropdown.tsx",
    "packages/gui/src/components/walletConnect/WalletConnectMetadata.tsx",
    "packages/gui/src/components/walletConnect/WalletConnectProvider.tsx",
    "packages/wallets/src/components/AddressBookAutocomplete.tsx",
    "packages/wallets/src/components/ClawbackClaimTransactionDialog.tsx",
    "packages/wallets/src/components/PasteMnemonic.tsx",
    "packages/wallets/src/components/Wallet.tsx",
    "packages/wallets/src/components/WalletAdd.tsx",
    "packages/wallets/src/components/WalletConnections.tsx",
    "packages/wallets/src/components/WalletEmptyDialog.tsx",
    "packages/wallets/src/components/WalletHeader.tsx",
    "packages/wallets/src/components/WalletHistory.tsx",
    "packages/wallets/src/components/WalletHistoryClawbackChip.tsx",
    "packages/wallets/src/components/WalletHistoryPending.tsx",
    "packages/wallets/src/components/WalletImport.tsx",
    "packages/wallets/src/components/WalletReceiveAddress.tsx",
    "packages/wallets/src/components/WalletReceiveAddressField.tsx",
    "packages/wallets/src/components/WalletRenameDialog.tsx",
    "packages/wallets/src/components/WalletSend.tsx",
    "packages/wallets/src/components/WalletSendTransactionResultDialog.tsx",
    "packages/wallets/src/components/WalletStatus.tsx",
    "packages/wallets/src/components/WalletStatusHeight.tsx",
    "packages/wallets/src/components/WalletTokenCard.tsx",
    "packages/wallets/src/components/Wallets.tsx",
    "packages/wallets/src/components/WalletsDropdown.tsx",
    "packages/wallets/src/components/WalletsManageTokens.tsx",
    "packages/wallets/src/components/card/WalletCardCRCatApprove.tsx",
    "packages/wallets/src/components/card/WalletCardCRCatRestrictions.tsx",
    "packages/wallets/src/components/cat/WalletCAT.tsx",
    "packages/wallets/src/components/cat/WalletCATCreateExistingSimple.tsx",
    "packages/wallets/src/components/cat/WalletCATCreateSimple.tsx",
    "packages/wallets/src/components/cat/WalletCATList.tsx",
    "packages/wallets/src/components/cat/WalletCATSelect.tsx",
    "packages/wallets/src/components/cat/WalletCATSend.tsx",
    "packages/wallets/src/components/cat/WalletCATTAILDialog.tsx",
    "packages/wallets/src/components/crCat/CrCatApprovePendingDialog.tsx",
    "packages/wallets/src/components/crCat/CrCatAuthorizedProviders.tsx",
    "packages/wallets/src/components/crCat/CrCatFlags.tsx",
    "packages/wallets/src/components/create/WalletCreate.tsx",
    "packages/wallets/src/components/create/WalletCreateCard.tsx",
    "packages/wallets/src/components/create/WalletCreateList.tsx",
    "packages/wallets/src/components/standard/WalletStandard.tsx",
    "packages/wallets/src/components/standard/WalletStandardCards.tsx",
    "packages/wallets/src/hooks/useClawbackDefaultTime.tsx",
    "packages/wallets/src/hooks/useHiddenWallet.ts",
    "packages/wallets/src/hooks/useIsWalletSynced.ts",
    "packages/wallets/src/hooks/useWallet.ts",
    "packages/wallets/src/hooks/useWalletHumanValue.ts",
    "packages/wallets/src/hooks/useWalletState.ts",
    "packages/wallets/src/hooks/useWalletTransactions.ts",
    "packages/wallets/src/hooks/useWalletsList.ts",
    "packages/wallets/src/utils/getWalletPrimaryTitle.ts",
    "packages/wallets/src/utils/getWalletSyncingStatus.ts",
    "packages/wallets/src/utils/isCATWalletPresent.ts",
]

target_scopes = [
    "Critical: Unauthorized signing, spend, transfer, offer acceptance/cancellation, clawback claim, payout change, or balance/accounting change affecting XCH, CAT, CR-CAT, NFT, DID, VC, DataLayer, or pooled farming rewards",
    "Critical: Secret exposure or signing-context confusion that lets an unprivileged actor obtain mnemonic, passphrase, wallet secrets, WalletConnect approval authority, or valid signatures/transactions for the wrong wallet, profile, DID, NFT, or address",
    "High: Bypass of passphrase, profile, keyring-migration, auto-login, wallet-selection, WalletConnect approval, offer confirmation, signing approval, or custody/clawback restrictions with direct security impact",
    "High: Corruption, spoofing, or unsafe trust of RPC, event, offer, NFT metadata, DataLayer, notification, or WalletConnect state that causes a user to approve, import, sign, send, revoke, burn, join, or display the wrong asset, identity, amount, destination, or status",
    "High: Unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content that produces direct asset loss, approval hijack, persistent lockout, or other concrete wallet security impact",
]


def question_generator(target_file: str) -> str:
    """
    Generate exploit-focused audit + fuzzing questions for one Chia GUI target.

    ```
    target_file format:
    "'File Name: packages/gui/src/components/offers/OfferImport.tsx -> Scope: High: Corruption, spoofing, or unsafe trust of RPC, event, offer, NFT metadata, DataLayer, notification, or WalletConnect state with direct security impact'"
    ```
    """

    prompt = f"""
    ```

    Generate exploit-focused security audit and fuzzing questions for this exact Chia GUI target:

    {target_file}

    Project context:
    Chia GUI is an Electron/React wallet application and TS monorepo. In-scope production logic includes RPC/WebSocket client layers, Redux/query state, wallet send/receive/import flows, offers and offer builder flows, NFT/DID/VC/DataLayer actions, passphrase and profile handling, WalletConnect sessions and approvals, address book and notification flows, pool and payout actions, external link/file/import handling, and security-sensitive app boot/persistence logic.

    Core invariants:
    * No unprivileged input may cause unauthorized signing, sending, claiming, revoking, burning, offer execution, payout updates, or wallet/accounting changes.
    * Wallet, profile, DID, NFT, CAT, VC, and WalletConnect actions must stay bound to the correct identity, asset, amount, and destination.
    * Secrets, passphrases, mnemonics, approval state, and imported payloads must never leak or be reused across the wrong context.
    * Untrusted RPC/events/offers/metadata/files/URLs must not spoof state or bypass confirmation and validation gates.

    Rules:
    * Treat `File Name:` as the exact file/module and `Scope:` as the only impact to target.
    * Assume full repo context is accessible; do not ask for code or say files are missing.
    * Generate 20 to 30 high-signal questions focused only on Critical or High impact.
    * At least 70% must be multi-step flow, invariant, fuzz, accounting, state-transition, or cross-module questions.
    * Every question must be testable by PoC, unit test, fuzz test, invariant test, differential test, or local integration test.
    * Avoid generic checklists, repeated root causes, best-practice items, and low/medium findings.
    * Do not generate pure clickjacking, self-XSS, UI polish, or resource-only questions unless they cause direct allowed impact.
    * Attacker is unprivileged: malicious dApp or WalletConnect peer, crafted offer/import file, hostile NFT metadata/content, malicious address/notification payload, remote counterparty, or attacker-controlled on-chain/RPC data within normal product use.
    * Exclude host compromise, leaked keys, compromised local daemon by assumption alone, dependency compromise, phishing, malicious app changes, tests, mocks, generated files, scripts, docs, and localization-only issues.

    High-value attack surfaces:
    * Wallet send/import/claim flows, CAT and CR-CAT restrictions, clawback timing, payout instruction changes, offer building/import/accept/cancel, and royalty calculation.
    * WalletConnect session setup, metadata, approval prompts, origin/account binding, request routing, and persistence across profiles or auto-login.
    * NFT, DID, VC, DataLayer, and notification flows that consume untrusted metadata, hashes, URIs, files, RPC events, or imported records.
    * Passphrase prompts, keyring migration, auth gating, profile switching, persistent settings, cached approval state, and external link/file opening.
    * Address parsing/normalization, amount conversion, RPC response shaping, event subscriptions, race/order issues, and stale state causing wrong-wallet or wrong-asset actions.

    Each question must include:
    1. target function/module;
    2. attacker action;
    3. preconditions;
    4. call sequence;
    5. invariant tested;
    6. scoped impact;
    7. proof idea.

    Output only valid Python. No markdown. No explanations.

    questions = [
    "[File: {target_file}] [Function: symbol_or_module] Can an unprivileged ATTACKER_ACTION under PRECONDITIONS trigger CALL_SEQUENCE, violating INVARIANT, causing scoped impact: SCOPE_IMPACT? Proof idea: fuzz/state-test PARAMETERS and assert EXPECTED_PROPERTY.",
    ]
    """
    return prompt


def audit_format(question: str) -> str:
    """
    Generate a focused Chia GUI exploit-question validation prompt.
    """
    return f"""# QUESTION SCAN PROMPT

## Exploit Question
{question}

## Scope Rules
- Audit only production Chia GUI code in scope: RPC/client state, wallet and asset flows, offers, NFTs, DIDs, VCs, DataLayer, WalletConnect, auth/passphrase/profile logic, pool payout flows, notifications, address book, and external file/URL handling.
- Ignore tests, docs, mocks, generated files, scripts, fixtures, locales, assets, build output, package metadata, and purely visual-only components unless the claim proves direct Critical/High wallet impact.
- This protocol pays only High and Critical issues; reject low, medium, best-practice, privacy-only, and resource-only reports.

## Objective
Decide whether the question leads to a real, reachable Chia GUI vulnerability.
The attacker must be unprivileged and enter through WalletConnect, offer/import/QR/file input, NFT or notification metadata, RPC/event/state handling, external URL/content handling, or another production workflow implemented in this repo.
Prefer #NoVulnerability unless the path is concrete, local-testable, and bounty-grade.

## Allowed Impact Scope
Only these impacts are valid:
- Critical: Unauthorized signing, spend, transfer, offer acceptance/cancellation, clawback claim, payout change, or balance/accounting change affecting XCH, CAT, CR-CAT, NFT, DID, VC, DataLayer, or pooled farming rewards
- Critical: Secret exposure or signing-context confusion that lets an unprivileged actor obtain mnemonic, passphrase, wallet secrets, WalletConnect approval authority, or valid signatures/transactions for the wrong wallet, profile, DID, NFT, or address
- High: Bypass of passphrase, profile, keyring-migration, auto-login, wallet-selection, WalletConnect approval, offer confirmation, signing approval, or custody/clawback restrictions with direct security impact
- High: Corruption, spoofing, or unsafe trust of RPC, event, offer, NFT metadata, DataLayer, notification, or WalletConnect state that causes a user to approve, import, sign, send, revoke, burn, join, or display the wrong asset, identity, amount, destination, or status
- High: Unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content that produces direct asset loss, approval hijack, persistent lockout, or other concrete wallet security impact

## Method
1. Trace the attacker-controlled entrypoint.
2. Map it to exact production Chia GUI files/functions.
3. Check guards for wallet/profile binding, passphrase/auth state, approval prompts, destination/address validation, amount conversion, imported payload validation, URL/content handling, RPC/event trust boundaries, and persistence/race behavior.
4. Prove root cause with file/function/line references and a reproducible PoC or test plan.
5. Reject if existing validation prevents the exploit or the final impact is not one allowed High/Critical impact.

## Reject Immediately
- Requires leaked keys, local host compromise, dependency compromise, broken cryptography, phishing/social engineering, malicious user-installed app changes, or unsupported external assumptions.
- Only affects tests, docs, configs, scripts, mocks, generated code, locales, assets, logs, observability, or non-security correctness.
- External dependency behavior is the only cause.
- Impact is only misleading text without security consequence, rejected action, harmless render issue, local misconfiguration, temporary spam, theoretical risk, or resource use without direct Critical/High wallet impact.

## Output
If valid:

### Title
[Clear vulnerability statement] - ([File: file_path])

### Summary
### Finding Description
### Impact Explanation
### Likelihood Explanation
### Recommendation
### Proof of Concept

If invalid, output exactly:
#NoVulnerability found for this question.
"""


def scan_format(report: str) -> str:
    """
    Generate a short cross-project analog scan prompt for Chia GUI.
    """
    prompt = f"""# ANALOG SCAN PROMPT

## External Report
{report}

## Access Rules (Strict)
- Treat production Chia GUI files in the provided scope as accessible context.
- Do not claim missing/inaccessible files.
- Do not scan tests, docs, build files, generated files, mocks, scripts, fixtures, locales, assets, package metadata, or purely presentational behavior as audited targets.
- Only High and Critical wallet/security impacts are payable; do not report medium/low/resource-only analogs.

## Objective
Use the external report's vulnerability class only as a hint.
Find an analog only if Chia GUI has its own reachable root cause in wallet flows, RPC/event state handling, offers, WalletConnect, NFT/DID/VC/DataLayer actions, passphrase/auth/profile logic, or external URL/file/content handling.
The attacker must be unprivileged and the impact must match the allowed Chia GUI impacts below.

## Allowed Impact Scope
Only these impacts are valid:
- Critical: Unauthorized signing, spend, transfer, offer acceptance/cancellation, clawback claim, payout change, or balance/accounting change affecting XCH, CAT, CR-CAT, NFT, DID, VC, DataLayer, or pooled farming rewards
- Critical: Secret exposure or signing-context confusion that lets an unprivileged actor obtain mnemonic, passphrase, wallet secrets, WalletConnect approval authority, or valid signatures/transactions for the wrong wallet, profile, DID, NFT, or address
- High: Bypass of passphrase, profile, keyring-migration, auto-login, wallet-selection, WalletConnect approval, offer confirmation, signing approval, or custody/clawback restrictions with direct security impact
- High: Corruption, spoofing, or unsafe trust of RPC, event, offer, NFT metadata, DataLayer, notification, or WalletConnect state that causes a user to approve, import, sign, send, revoke, burn, join, or display the wrong asset, identity, amount, destination, or status
- High: Unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content that produces direct asset loss, approval hijack, persistent lockout, or other concrete wallet security impact

## Method
1. Classify the external bug class: auth bypass, approval/signing confusion, accounting bug, unsafe import/content handling, WalletConnect/session flaw, state spoofing, persistence/race bug, or state corruption.
2. Map only to exact Chia GUI production files/functions.
3. Prove attacker path, missing/insufficient guard, and exact High/Critical impact.
4. Reject if Chia GUI validation blocks it or the analogy is only superficial.

## Disqualify Immediately
- No reachable unprivileged entry path.
- Requires leaked keys, host compromise, dependency compromise, cryptographic break, phishing/social engineering, or unsupported assumptions.
- Test/docs/config/build/generated/mock/locale/asset/local-only issue.
- Impact is temporary spam, logging, observability, visual-only behavior, rejected action, harmless render issue, non-security correctness, or theory without protocol impact.

## Output (Strict)
If valid analog exists, output:

### Title
[Clear vulnerability statement] - ([File: file_path])

### Summary
### Finding Description
### Impact Explanation
### Likelihood Explanation
### Recommendation
### Proof of Concept

If not, output exactly:
#NoVulnerability found for this question.

No extra text.
"""
    return prompt


def validation_format(report: str) -> str:
    """
    Generate a strict Chia GUI bounty-style validation prompt for security claims.
    """
    prompt = f"""# VALIDATION PROMPT

## Security Claim
{report}

## Rules
- Validate only the submitted claim against Chia GUI production code and SECURITY.md.
- Do not invent a new vulnerability or upgrade severity unless the evidence proves it.
- This protocol pays only High and Critical issues; reject low, medium, informational, best-practice, resource-only, privacy-only, and speculative reports.
- A valid report must be triggerable by an unprivileged dApp, WalletConnect peer, crafted offer/file/QR/import payload, hostile metadata/content source, remote counterparty, or attacker-controlled RPC/event input through code in this repo.
- Reject leaked keys, host compromise, dependency-only behavior, cryptographic breaks, phishing, victim mistakes outside the product, malicious user-installed app changes, local misconfiguration, and unsupported assumptions.

## In-Scope Protocol Areas
- RPC and WebSocket client layers, request/response shaping, event subscriptions, and Redux/query state updates.
- Wallet send/receive/import/sign/claim flows, CAT and CR-CAT restrictions, clawback, payout updates, offers, NFTs, DIDs, VCs, DataLayer, and WalletConnect.
- Passphrase prompts, keyring migration, auth gating, profile switching, auto-login, persistence, cached approvals, and external link/file/content handling.
- Notification, address book, metadata rendering, and embedded/external content paths only where a direct High/Critical impact is proven.
- App boot, route gating, and security-sensitive settings flows that can change signing or asset behavior.

Reject tests, docs, mocks, generated files, scripts, locales, assets, local fixtures, vendored libraries, purely stylistic UI issues, and non-security correctness unless the claim proves direct High/Critical wallet impact.

## Allowed Impact Scope
Only these impacts are valid:
- Critical: Unauthorized signing, spend, transfer, offer acceptance/cancellation, clawback claim, payout change, or balance/accounting change affecting XCH, CAT, CR-CAT, NFT, DID, VC, DataLayer, or pooled farming rewards
- Critical: Secret exposure or signing-context confusion that lets an unprivileged actor obtain mnemonic, passphrase, wallet secrets, WalletConnect approval authority, or valid signatures/transactions for the wrong wallet, profile, DID, NFT, or address
- High: Bypass of passphrase, profile, keyring-migration, auto-login, wallet-selection, WalletConnect approval, offer confirmation, signing approval, or custody/clawback restrictions with direct security impact
- High: Corruption, spoofing, or unsafe trust of RPC, event, offer, NFT metadata, DataLayer, notification, or WalletConnect state that causes a user to approve, import, sign, send, revoke, burn, join, or display the wrong asset, identity, amount, destination, or status
- High: Unsafe handling of external URLs, files, QR/import payloads, rendered metadata, or embedded content that produces direct asset loss, approval hijack, persistent lockout, or other concrete wallet security impact

## Required Validation Checks
All must pass:
1. Exact in-scope file, function, and line/code references.
2. Clear root cause and broken authorization/accounting/identity-binding/approval/trust-boundary invariant.
3. Reachable exploit path: preconditions -> attacker action -> trigger -> bad result.
4. Existing guards reviewed and shown insufficient.
5. Concrete allowed High/Critical impact with realistic likelihood.
6. Reproducible proof path: unit PoC, deterministic integration test, invariant test, fuzz test, fork test, or exact local steps.
7. No rejection reason from SECURITY.md, privileges, scope exclusions, or known intended behavior.

## Output
If valid, output exactly:

Audit Report

## Title
[Clear vulnerability statement] - ([File: file_path])

## Summary
[2-3 sentence summary of the bug and impact]

## Finding Description
[Exact code path, root cause, exploit flow, and why existing checks fail]

## Impact Explanation
[Concrete allowed Chia GUI security impact and severity rationale]

## Likelihood Explanation
[Attacker capability, required conditions, feasibility, repeatability]

## Recommendation
[Specific fix guidance]

## Proof of Concept
[Minimal reproducible steps or fuzz/invariant/fork test plan]

If invalid, output exactly:
#NoVulnerability found for this question.

Output only one of the two outcomes above. No extra text.
"""
    return prompt
