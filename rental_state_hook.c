
#include "hookapi.h"
#include <stdint.h>

int64_t hook(uint32_t reserved) {

    TRACESTR("HOOK FIRED");

    // checking if the incoming transaction is not going to

    uint8_t RENTAL_IN_PROGRESS_AMOUNT_KEY = 17;
    uint32_t INITIAL_RENTAL_NUM = 1;

    TRACESTR("Reading INITIAL_RENTAL_NUM and transaction type");
    int64_t num = state(SBUF(INITIAL_RENTAL_NUM), SBUF(RENTAL_IN_PROGRESS_AMOUNT_KEY));
    int64_t tt = otxn_type();
    if(num < 0) {
        TRACESTR("NO state value present");

        if(state_set(SBUF(INITIAL_RENTAL_NUM), SBUF(RENTAL_IN_PROGRESS_AMOUNT_KEY)) < 0) {
            rollback(SBUF("Initial state failure!"), 10);
        }
        TRACESTR("INITAL_STATE");
    }

    if(tt == ttNFTOKEN_CREATE_OFFER){
        int64_t state_val = state(SBUF(INITIAL_RENTAL_NUM), SBUF(RENTAL_IN_PROGRESS_AMOUNT_KEY));
        uint32_t modifiedValue = num - 1;

        if(state_set(SBUF(modifiedValue), SBUF(RENTAL_IN_PROGRESS_AMOUNT_KEY)) < 0) {
            rollback(SBUF("Fail to mutate state value"), 10);
        }
        TRACESTR("DECREMENT VALUE");
    }

    if(tt == ttACCOUNT_DELETE || tt == ttHOOK_SET) {
        int64_t state_val = state(SBUF(INITIAL_RENTAL_NUM), SBUF(RENTAL_IN_PROGRESS_AMOUNT_KEY));
        if(state_val > 0) {
            rollback(SBUF("Ongoing rentals, cannot mutate hook or delete account!"), 10);
        }
    }

    //check if incoming tx SET_HOOK

    // pointers and length variables for memos fields
    uint8_t *rental_type_ptr = 0, *rental_total_amount_ptr = 0,
            *rental_deadline_ptr = 0, *rental_escrow_condition_ptr;
    uint32_t rental_type_len = 0, rental_total_amount_len = 0,
            rental_deadline_len = 0, rental_escrow_condition_len;

    // CHECKING NFTokenID in HOOK STORE
    uint8_t incoming_nftoken_id[32] = {0};
    TRACEHEX(incoming_nftoken_id);
    uint64_t input_nftoken_id_len =
            otxn_field((uint32_t)(uintptr_t)incoming_nftoken_id, 32, sfNFTokenID);
    TRACEHEX(incoming_nftoken_id);
    if (input_nftoken_id_len < 0) {
        rollback(SBUF("RentalStateHook: nftTokenID missing!"), 10);
    }

    int8_t readNFTTokenID[32];
    int64_t nftoken_len = state(SBUF(readNFTTokenID), SBUF(incoming_nftoken_id));
    TRACEHEX(readNFTTokenID);
    TRACEVAR(nftoken_len);

    int64_t are_nfttoken_ids_equal = 0;

    if (nftoken_len == 32) {
        TRACESTR("NFToken already taken. The ID is in the store");
        are_nfttoken_ids_equal = 1;
    }

    if (are_nfttoken_ids_equal == 1) {
        rollback(SBUF("NFT of a given ID already exists"), 1);
    }

    // READING AND VALIDATION OF MEMOS INFO
    uint32_t memos;
    uint64_t memos_len = otxn_field(memos, 2048, sfMemos);

    if (memos_len <= 0) {
        accept(SBUF("No rental info presented in originating transaction. Tx "
                    "treated as regular NFT offer. Tx passed"),
               0);
    }

    // hook's Memos for NFTTOkenOffer on the acoount are defined as follow
    /**
     Memo: { MemoData: <rental_type>, MemoFormat: "signed/type", MemoType:
    [application defined] } REQUIRED Memo: { MemoData: <rental_deadline>,
    MemoFormat: "signed/deadline", MemoType: [application defined] }REQUIRED Memo:
    { MemoData: <rental_total_amount>, MemoFormat: "signed/amount", MemoType:
    [application defined] } REQUIRED Memo: { MemoData: <escrow_condition>,
    MemoFormat: "signed/condition", MemoType: [application defined] } REQUIRED IF
    rental_type = collaterall, otherwise OPTIONAL
    **/

    for (int i = 0; GUARD(3), i < 3; i++) {

        TRACEVAR(i);

        int64_t memo_lookup = sto_subarray(memos, memos_len, i);

        TRACEVAR(memo_lookup);

        if (memo_lookup <= 0) {
            rollback(SBUF("RentalStateHooks: Memo transaction did not contain enough "
                          "memo data."),
                     30);
        }

        uint8_t *memo_ptr = (uint8_t *)(uintptr_t)(SUB_OFFSET(memo_lookup) + memos);
        uint8_t memo_len = SUB_LENGTH(memo_lookup);

        trace(SBUF("Memo: "), (uint32_t)(uintptr_t)memo_ptr, memo_len, 1);

        // memos are nested inside an actual memo object, so we need to subfield
        // equivalently in JSON this would look like memo_array[i]["Memo"]
        memo_lookup = sto_subfield((uint32_t)(uintptr_t)memo_ptr, memo_len, sfMemo);
        memo_ptr = SUB_OFFSET(memo_lookup) + memo_ptr;
        memo_len = SUB_LENGTH(memo_lookup);

        // now we lookup the subfields of the memo itself
        // again, equivalently this would look like
        // memo_array[i]["Memo"]["MemoData"], ... etc.
        int64_t data_lookup = sto_subfield((uint32_t)(uintptr_t)memo_ptr, memo_len, sfMemoData);
        int64_t type_lookup = sto_subfield((uint32_t)(uintptr_t)memo_ptr, memo_len, sfMemoType);
        int64_t format_lookup = sto_subfield((uint32_t)(uintptr_t)memo_ptr, memo_len, sfMemoFormat);


        // if any of these lookups fail the request is malformed
        if (data_lookup < 0 || type_lookup < 0 || format_lookup < 0)
            rollback(SBUF("RentalStateHook: Memo transaction did not contain correct "
                          "memo type."),
                     40);

        // care must be taken to add the correct pointer to an offset returned by
        // sub_array or sub_field since we are working relative to the specific memo
        // we must add memo_ptr, NOT memos or something else
        uint8_t *data_ptr = SUB_OFFSET(data_lookup) + memo_ptr;
        uint32_t data_len = SUB_LENGTH(data_lookup);

        uint8_t *type_ptr = SUB_OFFSET(type_lookup) + memo_ptr;
        uint32_t type_len = SUB_LENGTH(type_lookup);

        uint8_t *format_ptr = SUB_OFFSET(format_lookup) + memo_ptr;
        uint32_t format_len = SUB_LENGTH(format_lookup);

        trace(SBUF("MEMO_TYPE: "), (uint32_t)(uintptr_t)type_ptr, type_len, 0);
        trace(SBUF("MEMO_DATA: "), (uint32_t)(uintptr_t)data_ptr, data_len, 0);
        trace(SBUF("MEMO_FORMAT: "), (uint32_t)(uintptr_t)format_ptr, format_len, 0);

        // we can use a helper macro to compare the format fields and determine
        // which MemoData is assigned to each pointer. Note that the last parameter
        // here tells the macro how many times we will hit this line so it in turn
        // can correctly configure its GUARD(), otherwise we will get a guard
        // violation
        int is_rental_type = 0, is_rental_total_amount = 0, is_rental_deadline = 0,
                is_escrow_condition = 0;
        BUFFER_EQUAL_STR_GUARD(is_rental_type, format_ptr, format_len,
                               "signed/type", 3);
        BUFFER_EQUAL_STR_GUARD(is_rental_total_amount, format_ptr, format_len,
                               "signed/total", 3);
        BUFFER_EQUAL_STR_GUARD(is_rental_deadline, format_ptr, format_len,
                               "signed/deadline", 3);
        BUFFER_EQUAL_STR_GUARD(is_escrow_condition, format_ptr, format_len,
                               "signed/condition", 3);

        if (is_rental_type) {
            TRACESTR("RENTAL_TYPE");
            rental_type_ptr = data_ptr;
            rental_type_len = data_len;

        } else if (is_rental_total_amount) {
            TRACESTR("RENTAL_TOTAL_AMOUNT");
            rental_total_amount_ptr = data_ptr;
            rental_total_amount_len = data_len;

        } else if (is_rental_deadline) {
            TRACESTR("RENTAL_DEADLINE");
            rental_deadline_ptr = data_ptr;
            rental_deadline_len = data_len;

        } else if (is_escrow_condition) {
            TRACESTR("RENTAL_CONDITION");
            rental_escrow_condition_ptr = data_ptr;
            rental_escrow_condition_len = data_len;
        }
    }

    int is_collateral_free = 0;
    uint8_t collateral_free_type[19] = {0x43,0x4F,0x4C,0x4C,0x41,0x54,0x45,0x52,0x41,0x4C,0x49,0x5A,0x45,0x44, 0x5F,0x46,0x52,0x45,0x45};
    BUFFER_EQUAL(is_collateral_free, collateral_free_type, rental_type_ptr, 19);

    int is_collateral = 0;
    uint8_t collateral_type[14] = {0x43,0x4F,0x4C,0x4C,0x41,0x54,0x45,0x52,0x41,0x4C,0x49,0x5A,0x45,0x44};
    BUFFER_EQUAL(is_collateral, collateral_type, rental_type_ptr, 14);

    if (!is_collateral_free && !is_collateral) {
        rollback(SBUF("No rental type provided"), 20);
    }

    TRACEVAR(is_collateral_free);
    TRACEVAR(rental_type_ptr);
    TRACEVAR(rental_total_amount_ptr);
    TRACEVAR(rental_deadline_ptr);

    if ((is_collateral_free &&
         !(rental_type_ptr && rental_total_amount_ptr && rental_deadline_ptr)) ||
        (is_collateral &&
         !(rental_type_ptr && rental_total_amount_ptr && rental_deadline_ptr &&
           rental_escrow_condition_ptr))) {
        uint8_t escrow_hook_namespace_hash[32];
        int64_t bytes_written = hook_hash(SBUF(escrow_hook_namespace_hash), 1);
        TRACEHEX(escrow_hook_namespace_hash);
        hook_skip(SBUF(escrow_hook_namespace_hash), 0);
        rollback(SBUF("Invalid rental parameters"), 20);
    } else {
        TRACESTR("SAVING NFTOKENID TO THE STORE");
        TRACEVAR(incoming_nftoken_id);
        int64_t tx_len =
                state_set(SBUF(incoming_nftoken_id), SBUF(incoming_nftoken_id));
        if (tx_len < 0) {
            rollback(SBUF("New NFTokenID save to store failed"), 1);
        } else {
            TRACESTR("New NFTokenID saved to the store");
        }
        accept(SBUF("Offer accepted and passed on ledger/next hook"), (uint64_t)(uintptr_t)0);
    }

    _g(1,
       1); // every hook needs to import guard function and use it at least once
    // unreachable
    return 0;
}