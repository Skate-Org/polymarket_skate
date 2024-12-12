use anchor_lang::prelude::*;
use anchor_spl::token_interface::{
        TokenAccount, Mint, close_account,
        TokenInterface, TransferChecked, transfer_checked
    };
// use anchor_lang::solana_program::sysvar::instructions::{ID as IX_ID};
pub mod error;
pub mod ed25519;

declare_id!("E98KDQN4NuhPcj4KD82pZj122KxYZ9dNhsNaAbPXLkeY");    

/*
    TODO: Link User wallet and Gateway
*/
#[program]
pub mod polymarket_skate {

    use anchor_lang::solana_program::sysvar::instructions::load_instruction_at_checked;
    use anchor_spl::token_interface::CloseAccount;

    use super::*;

    /// Initializes a user wallet. Each user can only initialize once.
    pub fn initialize_user_wallet(ctx: Context<InitializeUserWallet>) -> Result<()> {
        let user_wallet = &mut ctx.accounts.user_wallet;
        user_wallet.owner = *ctx.accounts.user.key;
        user_wallet.master = *ctx.accounts.master.key;
        user_wallet.action_id = 1;
        emit!(UserWalletInitialized {
            owner: user_wallet.owner,
            master: user_wallet.master,
            action_id: user_wallet.action_id,
        });
        Ok(())
    }
    
    pub fn place_buy_order(
        ctx: Context<PlaceBuyOrder>,
        msg: Vec<u8>,
        sig: [u8; 64],
    ) -> Result<()> {
        let ix = load_instruction_at_checked(0, &ctx.accounts.ix_sysvar)?;
        ed25519::verify_ed25519_ix(&ix, &ctx.accounts.user.key.to_bytes(), &msg, &sig)?;
        let order_msg = Order::try_from_slice(&msg)?;
        require!(order_msg.order_type == 0, CustomError::InvalidOrderType);
    
        // Get the bump for 'user_wallet'
        let bump = ctx.bumps.user_wallet;
    
        // Prepare the seeds for the PDA
        let seeds = &[
            b"user-wallet",
            ctx.accounts.user.key.as_ref(),
            ctx.accounts.master.key.as_ref(),
            &[bump],
        ];
        let signer = &[&seeds[..]];
    
        // Transfer USDT from user's USDT account to the buy order's USDT account
        {
            let cpi_accounts = TransferChecked {
                from: ctx.accounts.user_wallet_usdt_account.to_account_info(),
                to: ctx.accounts.buy_order_usdt_account.to_account_info(),
                authority: ctx.accounts.user_wallet.to_account_info(),
                mint: ctx.accounts.usdt_mint.to_account_info(),
            };
            let cpi_program = ctx.accounts.token_program.to_account_info();
            let cpi_ctx = CpiContext::new_with_signer(cpi_program, cpi_accounts, signer);
            transfer_checked(cpi_ctx, order_msg.amount, ctx.accounts.usdt_mint.decimals)?;
        }
    
        // Borrow mutable references after CPI transfer
        let user_wallet = &mut ctx.accounts.user_wallet;
        // Check that order expiration is not more than 24 hours from now
        // let current_timestamp = Clock::get()?.unix_timestamp as u64;
        // let twenty_four_hours = 24 * 60 * 60; // 24 hours in seconds
        // require!(
        //     order_msg.expiration <= current_timestamp + twenty_four_hours,
        //     CustomError::OrderExpired
        // );
        ctx.accounts.order.action_id = user_wallet.action_id;
        ctx.accounts.order.amount = order_msg.amount;
        ctx.accounts.order.expiration = order_msg.expiration;
        ctx.accounts.order.owner = order_msg.owner;
        ctx.accounts.order.token_id = order_msg.token_id.clone();
    
        let token_id_str = String::from_utf8(ctx.accounts.order.token_id.to_vec()).unwrap();
    
        // Emit event for order
        emit!(BuyOrderPlaced {
            action_id: ctx.accounts.order.action_id,
            amount: ctx.accounts.order.amount,
            expiration: ctx.accounts.order.expiration,
            owner: ctx.accounts.order.owner,
            token_id: token_id_str.clone(),
        });
    
        msg!(
            "Order initialized with action_id: {}, amount: {}, expiration: {}, owner: {}, token_id: {}, order_type: {}",
            ctx.accounts.order.action_id,
            ctx.accounts.order.amount,
            ctx.accounts.order.expiration,
            ctx.accounts.order.owner,
            token_id_str,
            ctx.accounts.order.order_type
        );
    
        // Increment action_id
        user_wallet.action_id += 1;
        Ok(())
    }

    pub fn place_sell_order(
        ctx: Context<PlaceSellOrder>,
        msg: Vec<u8>,
        sig: [u8; 64],
    ) -> Result<()> {
        let user_wallet = &mut ctx.accounts.user_wallet;
        let sell_order = &mut ctx.accounts.sell_order;

        let ix = load_instruction_at_checked(0, &ctx.accounts.ix_sysvar)?;

        ed25519::verify_ed25519_ix(&ix, &ctx.accounts.user.key.to_bytes(), &msg, &sig)?;

        let order = Order::try_from_slice(&msg)?;
        // let current_timestamp = Clock::get()?.unix_timestamp as u64;
        // let twenty_four_hours = 24 * 60 * 60; // 24 hours in seconds
        // require!(
        //     order.expiration <= current_timestamp + twenty_four_hours,
        //     CustomError::OrderExpired
        // );
        require!(order.order_type == 1, CustomError::InvalidOrderType);
        // Define sell params and update state
        sell_order.action_id = order.action_id;
        sell_order.amount = order.amount;
        sell_order.expiration = order.expiration;
        sell_order.owner = order.owner;
        sell_order.token_id = order.token_id.clone();
        sell_order.order_type = order.order_type;

        let token_id_str = String::from_utf8(sell_order.token_id.to_vec()).unwrap();

        emit!(SellOrderPlaced {
            action_id: sell_order.action_id,
            ct_amount: sell_order.amount,
            expiration: sell_order.expiration,
            owner: sell_order.owner,
            token_id: token_id_str.clone(),
        });
        msg!(
            "Sell order initialized with action_id: {}, ct_amount: {}, expiration: {}, owner: {}, token_id: {}, order_type: {}",
            sell_order.action_id,
            sell_order.amount,
            sell_order.expiration,
            sell_order.owner,
            token_id_str,
            sell_order.order_type
        );
        // Increment action_id
        user_wallet.action_id += 1;
    
        Ok(())
    }
    
    pub fn withdraw_order(ctx: Context<WithdrawOrder>, msg: Vec<u8>) -> Result<()> {
        let order = &ctx.accounts.order;
        let order2 = Order::try_from_slice(&msg)?;
        
        require!(&order2.action_id == &order.action_id, CustomError::InvalidActionId);
        
        // let ix = load_instruction_at_checked(0, &ctx.accounts.ix_sysvar)?;
        // ed25519::verify_ed25519_ix(&ix, &ctx.accounts.user.key.to_bytes(), &msg, &sig)?;
        // implement expiration check
        require!(order.expiration < (Clock::get()?.unix_timestamp) as u64, CustomError::OrderNotExpired);
        require!(order2.order_type == 2, CustomError::InvalidOrderType);

        // For buy orders carry out the fund transfer and close the buy_order_usdt_account
        if order.order_type == 0 {
            let amount = ctx.accounts.buy_order_usdt_account.as_ref().unwrap().amount;
            let order_seeds: &[&[u8]; 5] = &[
                b"order",
                &order.action_id.to_le_bytes()[..],
                ctx.accounts.user.key.as_ref(),
                ctx.accounts.master.key.as_ref(),
                &[ctx.bumps.order],
            ];
    
            let signer = &[&order_seeds[..]];
    
            let cpi_accounts = TransferChecked {
                from: ctx.accounts.buy_order_usdt_account.as_ref().unwrap().to_account_info(),
                to: ctx.accounts.user_usdt_account.as_ref().unwrap().to_account_info(),
                authority: ctx.accounts.order.to_account_info(),
                mint: ctx.accounts.usdt_mint.to_account_info(),
            };
    
            let cpi_program = ctx.accounts.token_program.to_account_info();
            let cpi_ctx = CpiContext::new_with_signer(cpi_program, cpi_accounts, signer);
            transfer_checked(cpi_ctx, amount, ctx.accounts.usdt_mint.decimals)?;
        
            // 2. Close buy_order_usdt_account
            let cpi_accounts: CloseAccount<'_> = CloseAccount {
                account: ctx.accounts.buy_order_usdt_account.as_ref().unwrap().to_account_info(),
                destination: ctx.accounts.master.to_account_info(),
                authority: ctx.accounts.order.to_account_info(),
            };
            
            let cpi_program = ctx.accounts.token_program.to_account_info();
            let cpi_ctx = CpiContext::new_with_signer(cpi_program, cpi_accounts, signer);
            close_account(cpi_ctx)?;
        }
        let token_id_str = String::from_utf8(ctx.accounts.order.token_id.to_vec()).unwrap();
        msg!("Order closed with action_id: {}, amount: {}, expiration: {}, owner: {}, token_id: {}",
            order.action_id,
            order.amount,
            order.expiration,
            order.owner,
            token_id_str
        );
        emit!(OrderWithdrawn {
            action_id: order.action_id,
            owner: order.owner,
        });

        ctx.accounts.user_wallet.action_id += 1;

        Ok(())
    }

    pub fn confirm_order(ctx: Context<ConfirmOrder>, sell_amount: u64) -> Result<()> {
        msg!("Confirming order");
        let order = &ctx.accounts.order;
        
        // Implement necessary checks
        require!(
            order.expiration >= Clock::get()?.unix_timestamp as u64,
            CustomError::OrderExpired
        );
        require!(order.order_type == 0 || order.order_type == 1, CustomError::InvalidOrderType);
        // Transfer USDT from buy_order_usdt_account to master's USDT account
        let order_seeds = &[
            b"order",
            &order.action_id.to_le_bytes()[..],
            ctx.accounts.user.key.as_ref(),
            ctx.accounts.master.key.as_ref(),
            &[ctx.bumps.order],
        ];
        let signer = &[&order_seeds[..]];
        if order.order_type == 0 {
            let buy_amount = ctx.accounts.buy_order_usdt_account.as_ref().unwrap().amount;
            let cpi_accounts = TransferChecked {
                from: ctx.accounts.buy_order_usdt_account.as_ref().unwrap().to_account_info(),
                to: ctx.accounts.master_usdt_account.to_account_info(),
                authority: ctx.accounts.order.to_account_info(),
                mint: ctx.accounts.usdt_mint.to_account_info(),
            };          
            let cpi_program = ctx.accounts.token_program.to_account_info();
            let cpi_ctx = CpiContext::new_with_signer(cpi_program.clone(), cpi_accounts, signer);
            transfer_checked(cpi_ctx, buy_amount, ctx.accounts.usdt_mint.decimals)?;
        
            // Close buy_order_usdt_account
            let cpi_accounts = CloseAccount {
                account: ctx.accounts.buy_order_usdt_account.as_ref().unwrap().to_account_info(),
                destination: ctx.accounts.master.to_account_info(),
                authority: ctx.accounts.order.to_account_info(),
            };
            let cpi_ctx = CpiContext::new_with_signer(cpi_program.clone(), cpi_accounts, signer);
            close_account(cpi_ctx)?;
        } else if order.order_type == 1 {
            // Transfer USDT from master's account to user's wallet account
            let cpi_accounts = TransferChecked {
                from: ctx.accounts.master_usdt_account.to_account_info(),
                to: ctx.accounts.user_wallet_usdt_account.to_account_info(),
                authority: ctx.accounts.master.to_account_info(), // Use master as authority
                mint: ctx.accounts.usdt_mint.to_account_info(),
            };
            let cpi_program = ctx.accounts.token_program.to_account_info();
            let cpi_ctx = CpiContext::new(cpi_program.clone(), cpi_accounts);
            transfer_checked(cpi_ctx, sell_amount, ctx.accounts.usdt_mint.decimals)?;
        
        } else {
            return Err(CustomError::InvalidOrderType.into());
        }
        let token_id_str = String::from_utf8(order.token_id.to_vec()).unwrap();
        emit!(OrderConfirmed {
            action_id: order.action_id,
            amount: order.amount,
            token_id: token_id_str.clone(),
            owner: order.owner,
        });
        msg!(
            "Order confirmed with action_id: {}, amount: {}, token_id: {}, owner: {}, sell_amount: {}, order_type: {}",
            order.action_id,
            order.amount,
            token_id_str,
            order.owner,
            sell_amount,
            order.order_type,
        );
    
        // Increment the action_id for the user's wallet
        ctx.accounts.user_wallet.action_id += 1;
    
        Ok(())
    }
    
}

#[derive(Accounts)]
pub struct InitializeUserWallet<'info> {
    /// The user initializing their wallet
    #[account(
        init,
        payer = payer,
        space = 8 + UserWallet::LEN,
        seeds = [b"user-wallet", user.key().as_ref(), master.key().as_ref()],
        bump
    )]
    pub user_wallet: Account<'info, UserWallet>,

    /// The user who owns the wallet
    pub user: Signer<'info>,

    /// CHECK: The master authority placing the order
    pub master: AccountInfo<'info>,

    #[account(mut)]
    pub payer: Signer<'info>, // Payer must be mutable

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct PlaceBuyOrder<'info> {
    /// CHECK: The user on whose behalf the order is being placed
    pub user: AccountInfo<'info>,

    /// The master authority placing the order
    #[account(mut)]
    pub master: Signer<'info>, // Payer is the master and must be mutable

    /// The user's wallet account (PDA)
    #[account(
        mut,
        seeds = [b"user-wallet", user.key().as_ref(), master.key().as_ref()],
        bump,
    )]
    pub user_wallet: Box<Account<'info, UserWallet>>,

    /// User's USDT associated token account (owned by user)
    #[account(
        mut,
        constraint = user_wallet_usdt_account.owner == user.key(),
        constraint = user_wallet_usdt_account.delegate == Some(user_wallet.key()).into(),
    )]
    pub user_wallet_usdt_account: InterfaceAccount<'info, TokenAccount>,

    /// The order account to be initialized (PDA)
    #[account(
        init,
        payer = master,
        space = 8 + Order::LEN,
        seeds = [
            b"order",
            user_wallet.action_id.to_le_bytes().as_ref(),
            user.key().as_ref(),
            master.key().as_ref(),
        ],
        bump,
        
    )]
    pub order: Box<Account<'info, Order>>,

    /// Buy order's USDT account to be initialized (PDA)
    #[account(
        init,
        payer = master,
        token::mint = usdt_mint,
        token::authority = order,
        seeds = [
            b"order-usdt-account",
            user_wallet.action_id.to_le_bytes().as_ref(),
            user.key().as_ref(),
            master.key().as_ref(),
        ],
        bump,
    )]
    pub buy_order_usdt_account: InterfaceAccount<'info, TokenAccount>,

    pub usdt_mint: InterfaceAccount<'info, Mint>,
    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,

    /// CHECK: Sysvar for instructions (used for signature verification)
    pub ix_sysvar: AccountInfo<'info>,
}

#[derive(Accounts)] 
pub struct PlaceSellOrder<'info> {
    /// The user's wallet PDA
    #[account(
        mut,
        seeds = [b"user-wallet", user.key().as_ref(), master.key().as_ref()],
        bump,
    )]
    pub user_wallet: Account<'info, UserWallet>,
    
    /// CHECK: The user on whose behalf the order is being placed
    pub user: AccountInfo<'info>,

    /// The master authority placing the sell order
    #[account(mut)]
    pub master: Signer<'info>,
    
    /// The sell order account to be initialized (PDA)
    #[account(
        init_if_needed,
        payer = master, // Changed from to `master` to reflect that master pays for the account
        space = 8 + Order::LEN,
        seeds = [
            b"order".as_ref(),
            user_wallet.action_id.to_le_bytes().as_ref(),
            user.key().as_ref(),
            master.key().as_ref(),
        ],
        bump,
    )]
    pub sell_order: Account<'info, Order>,
    
    /// The system program
    pub system_program: Program<'info, System>,

    ///CHECK: Sysvar for instructions (used for signature verification)
    pub ix_sysvar: AccountInfo<'info>,

}

#[derive(Accounts)]
pub struct ConfirmOrder<'info> {
    /// CHECK: The user on whose behalf the order is being confirmed
    pub user: AccountInfo<'info>,

    /// The master authority confirming the order
    #[account(mut)]
    pub master: Signer<'info>,

    /// The user's wallet account (PDA)
    #[account(
        mut,
        seeds = [b"user-wallet", user.key().as_ref(), master.key().as_ref()],
        bump,
    )]
    pub user_wallet: Account<'info, UserWallet>,

    /// The order account to be closed (PDA)
    #[account(
        mut,
        seeds = [
            b"order",
            order.action_id.to_le_bytes().as_ref(),
            user.key().as_ref(),
            master.key().as_ref(),
        ],
        bump,
        close = master,
        constraint = order.owner == user.key(), // Add this constraint for safety
    )]
    pub order: Account<'info, Order>,

    /// Buy order's USDT account to be closed (PDA)
    #[account(
        mut,
        seeds = [
            b"order-usdt-account",
            order.action_id.to_le_bytes().as_ref(),
            user.key().as_ref(),
            master.key().as_ref(),
        ],
        bump,
        token::authority = order,
    )]
    pub buy_order_usdt_account: Option<InterfaceAccount<'info, TokenAccount>>,

    /// Master's USDT associated token account (owned by master)
    #[account(
        mut,
        constraint = master_usdt_account.owner == master.key(),
    )]
    pub master_usdt_account: InterfaceAccount<'info, TokenAccount>,
   
    #[account(
        mut,
        constraint = user_wallet_usdt_account.owner == user.key(),
    )]
    pub user_wallet_usdt_account: InterfaceAccount<'info, TokenAccount>,
    pub usdt_mint: InterfaceAccount<'info, Mint>,
    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct WithdrawOrder<'info> {
    /// CHECK: The user on whose behalf the order is being withdrawn
    pub user: AccountInfo<'info>,

    /// The master authority withdrawing the order
    #[account(mut)]
    pub master: Signer<'info>,

    /// The user's wallet account (PDA)
    #[account(
        mut,
        seeds = [b"user-wallet", user.key().as_ref(), master.key().as_ref()],
        bump,
    )]
    pub user_wallet: Account<'info, UserWallet>,

    /// The order account to be closed (PDA)
    #[account(
        mut,
        seeds = [
            b"order",
            order.action_id.to_le_bytes().as_ref(),
            user.key().as_ref(),
            master.key().as_ref(),
        ],
        bump,
        close = master,
        constraint = order.owner == user.key(),      
    )]
    pub order: Account<'info, Order>,

    /// Buy order's USDT account to be closed (PDA)
    #[account(
        mut,
        seeds = [
            b"order-usdt-account",
            order.action_id.to_le_bytes().as_ref(),
            user.key().as_ref(),
            master.key().as_ref(),
        ],
        bump,
        token::authority = order,
    )]
    pub buy_order_usdt_account: Option<InterfaceAccount<'info, TokenAccount>>,

    /// User's USDT associated token account (owned by user)
    #[account(
        mut,
        constraint = user_usdt_account.owner == user.key(),
    )]
    pub user_usdt_account: Option<InterfaceAccount<'info, TokenAccount>>,

    pub usdt_mint: InterfaceAccount<'info, Mint>,
    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}


#[account]
pub struct UserWallet {
    pub owner: Pubkey,
    pub master: Pubkey,
    pub action_id: u64,
}

impl UserWallet {
    const LEN: usize = 32 + 32 + 8; // owner + master + action_id
}

#[account]

pub struct Order {
    pub action_id: u64,
    pub amount: u64, // usd_amount for buy, ct_amount for sell
    pub expiration: u64,
    pub owner: Pubkey,
    pub token_id: [u8;78],
    pub order_type: u8, // 0 for buy, 1 for sell, 2 for withdraw
}

impl Order {
    // Calculate the total length of the Order struct (excluding discriminator)
    pub const LEN: usize = 
        8                      // action_id
        + 8                    // amount
        + 8                    // expiration
        + 32                   // owner (Pubkey)
        + 78 // token_id 
        + 1;                   // order_type
}


#[error_code]
pub enum CustomError {
    #[msg("Invalid bet size!")]
    InvalidBetSize,
    #[msg("Order is expired!")]
    OrderExpired,
    #[msg("Order not expired!")]
    OrderNotExpired,
    #[msg("Bump not found for PDA.")]
    BumpNotFound,
    #[msg("Invalid order type!")]
    InvalidOrderType,
    #[msg("Invalid action id!")]
    InvalidActionId,
}

#[event]
pub struct BuyOrderPlaced {
    pub action_id: u64,
    pub amount: u64,
    pub expiration: u64,
    pub owner: Pubkey,
    pub token_id: String,
}

#[event]
pub struct SellOrderPlaced {
    pub action_id: u64,
    pub ct_amount: u64,
    pub expiration: u64,
    pub owner: Pubkey,
    pub token_id: String,
}

#[event]
pub struct OrderWithdrawn {
    pub action_id: u64,
    pub owner: Pubkey,
}

#[event]
pub struct UserWalletInitialized {
    pub owner: Pubkey,
    pub master: Pubkey,
    pub action_id: u64,
}

#[event]
pub struct SignatureVerified {
    pub signer: Pubkey,
    pub message: Vec<u8>,
    pub signature: [u8; 64],
}

#[event]
pub struct OrderConfirmed {
    pub action_id: u64,
    pub amount: u64,
    pub owner: Pubkey,
    pub token_id: String,
}

// const BUY_ORDER_EXPIRATION: u64 = 300; // 5 minutes in seconds
// const SELL_ORDER_EXPIRATION: u64 = 300; // 5 minutes in seconds
