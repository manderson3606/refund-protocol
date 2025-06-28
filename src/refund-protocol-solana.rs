//! Solana Refund Protocol Program

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};
use std::convert::TryInto;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS"); // Replace with your program ID

// Constants
const MAX_LOCKUP_SECONDS: i64 = 60 * 60 * 24 * 180; // 180 days

#[program]
pub mod refund_protocol {
    use super::*;

    pub fn initialize(
        ctx: Context<Initialize>,
        arbiter: Pubkey,
        eip712_name: String, 
        eip712_version: String
    ) -> Result<()> {
        let protocol_state = &mut ctx.accounts.protocol_state;
        protocol_state.arbiter = arbiter;
        protocol_state.token_mint = ctx.accounts.token_mint.key();
        protocol_state.nonce = 0;
        protocol_state.bump = *ctx.bumps.get("protocol_state").unwrap();
        Ok(())
    }

    pub fn pay(
        ctx: Context<Pay>,
        amount: u64,
        refund_to: Pubkey,
    ) -> Result<()> {
        if refund_to == Pubkey::default() {
            return err!(ErrorCode::RefundToIsZeroAddress);
        }

        let protocol_state = &mut ctx.accounts.protocol_state;
        let recipient = ctx.accounts.recipient.key();
        
        // Get recipient lockup seconds
        let recipient_lockup_seconds = ctx.accounts.recipient_info.lockup_seconds;
        
        // Transfer tokens to protocol vault
        let transfer_cpi_accounts = Transfer {
            from: ctx.accounts.payer_token_account.to_account_info(),
            to: ctx.accounts.protocol_vault.to_account_info(),
            authority: ctx.accounts.payer.to_account_info(),
        };
        
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new(cpi_program, transfer_cpi_accounts);
        token::transfer(cpi_ctx, amount)?;
        
        // Create payment
        let payment = &mut ctx.accounts.payment;
        payment.to = recipient;
        payment.amount = amount;
        payment.release_timestamp = Clock::get()?.unix_timestamp + recipient_lockup_seconds as i64;
        payment.refund_to = refund_to;
        payment.withdrawn_amount = 0;
        payment.refunded = false;
        payment.payment_id = protocol_state.nonce;
        payment.bump = *ctx.bumps.get("payment").unwrap();
        
        // Update recipient balance
        let recipient_balance = &mut ctx.accounts.recipient_info;
        recipient_balance.balance = recipient_balance.balance.checked_add(amount).unwrap();
        
        // Increment nonce
        protocol_state.nonce = protocol_state.nonce.checked_add(1).unwrap();
        
        emit!(PaymentCreated {
            payment_id: payment.payment_id,
            to: recipient,
            amount,
            release_timestamp: payment.release_timestamp,
            refund_to,
        });
        
        Ok(())
    }

    pub fn refund_by_recipient(ctx: Context<RefundByRecipient>) -> Result<()> {
        let payment = &ctx.accounts.payment;
        let payment_id = payment.payment_id;
        let payment_amount = payment.amount;
        let refund_to = payment.refund_to;
        
        if payment.refunded {
            return err!(ErrorCode::PaymentRefunded);
        }
        
        let recipient_info = &mut ctx.accounts.recipient_info;
        
        if payment_amount > recipient_info.balance {
            return err!(ErrorCode::InsufficientFunds);
        }
        
        // Update recipient balance
        recipient_info.balance = recipient_info.balance.checked_sub(payment_amount).unwrap();
        
        // Mark payment as refunded
        let payment = &mut ctx.accounts.payment;
        payment.refunded = true;
        
        // Transfer tokens from protocol vault to refund_to
        let seeds = &[
            b"protocol_state".as_ref(),
            &[ctx.accounts.protocol_state.bump],
        ];
        let signer = &[&seeds[..]];
        
        let transfer_cpi_accounts = Transfer {
            from: ctx.accounts.protocol_vault.to_account_info(),
            to: ctx.accounts.refund_to_token_account.to_account_info(),
            authority: ctx.accounts.protocol_state.to_account_info(),
        };
        
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new_with_signer(cpi_program, transfer_cpi_accounts, signer);
        token::transfer(cpi_ctx, payment_amount)?;
        
        emit!(Refund {
            payment_id,
            refund_to,
            amount: payment_amount,
        });
        
        Ok(())
    }

    pub fn refund_by_arbiter(ctx: Context<RefundByArbiter>) -> Result<()> {
        let payment = &ctx.accounts.payment;
        let payment_id = payment.payment_id;
        let payment_amount = payment.amount;
        let refund_to = payment.refund_to;
        let recipient = payment.to;
        
        if payment.refunded {
            return err!(ErrorCode::PaymentRefunded);
        }
        
        let recipient_info = &mut ctx.accounts.recipient_info;
        let arbiter_info = &mut ctx.accounts.arbiter_info;
        
        // Try to use recipient balance first
        if payment_amount <= recipient_info.balance {
            recipient_info.balance = recipient_info.balance.checked_sub(payment_amount).unwrap();
        } else {
            // Use arbiter balance
            if payment_amount > arbiter_info.balance {
                return err!(ErrorCode::InsufficientFunds);
            }
            
            arbiter_info.balance = arbiter_info.balance.checked_sub(payment_amount).unwrap();
            
            // Increase recipient debt
            recipient_info.debt = recipient_info.debt.checked_add(payment_amount).unwrap();
        }
        
        // Mark payment as refunded
        let payment = &mut ctx.accounts.payment;
        payment.refunded = true;
        
        // Transfer tokens from protocol vault to refund_to
        let seeds = &[
            b"protocol_state".as_ref(),
            &[ctx.accounts.protocol_state.bump],
        ];
        let signer = &[&seeds[..]];
        
        let transfer_cpi_accounts = Transfer {
            from: ctx.accounts.protocol_vault.to_account_info(),
            to: ctx.accounts.refund_to_token_account.to_account_info(),
            authority: ctx.accounts.protocol_state.to_account_info(),
        };
        
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new_with_signer(cpi_program, transfer_cpi_accounts, signer);
        token::transfer(cpi_ctx, payment_amount)?;
        
        emit!(Refund {
            payment_id,
            refund_to,
            amount: payment_amount,
        });
        
        Ok(())
    }

    pub fn settle_debt(ctx: Context<SettleDebt>) -> Result<()> {
        let recipient = ctx.accounts.recipient.key();
        settle_debt_internal(
            ctx.accounts.recipient_info.as_mut(),
            ctx.accounts.arbiter_info.as_mut(),
        )
    }

    pub fn deposit_arbiter_funds(ctx: Context<DepositArbiterFunds>, amount: u64) -> Result<()> {
        // Transfer tokens to protocol vault
        let transfer_cpi_accounts = Transfer {
            from: ctx.accounts.arbiter_token_account.to_account_info(),
            to: ctx.accounts.protocol_vault.to_account_info(),
            authority: ctx.accounts.arbiter.to_account_info(),
        };
        
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new(cpi_program, transfer_cpi_accounts);
        token::transfer(cpi_ctx, amount)?;
        
        // Update arbiter balance
        let arbiter_info = &mut ctx.accounts.arbiter_info;
        arbiter_info.balance = arbiter_info.balance.checked_add(amount).unwrap();
        
        Ok(())
    }

    pub fn withdraw_arbiter_funds(ctx: Context<WithdrawArbiterFunds>, amount: u64) -> Result<()> {
        let arbiter_info = &mut ctx.accounts.arbiter_info;
        
        if amount > arbiter_info.balance {
            return err!(ErrorCode::InsufficientFunds);
        }
        
        // Update arbiter balance
        arbiter_info.balance = arbiter_info.balance.checked_sub(amount).unwrap();
        
        // Transfer tokens from protocol vault to arbiter
        let seeds = &[
            b"protocol_state".as_ref(),
            &[ctx.accounts.protocol_state.bump],
        ];
        let signer = &[&seeds[..]];
        
        let transfer_cpi_accounts = Transfer {
            from: ctx.accounts.protocol_vault.to_account_info(),
            to: ctx.accounts.arbiter_token_account.to_account_info(),
            authority: ctx.accounts.protocol_state.to_account_info(),
        };
        
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new_with_signer(cpi_program, transfer_cpi_accounts, signer);
        token::transfer(cpi_ctx, amount)?;
        
        Ok(())
    }

    pub fn set_lockup_seconds(
        ctx: Context<SetLockupSeconds>,
        recipient: Pubkey,
        recipient_lockup_seconds: i64,
    ) -> Result<()> {
        if recipient_lockup_seconds > MAX_LOCKUP_SECONDS {
            return err!(ErrorCode::LockupSecondsExceedsMax);
        }
        
        let recipient_info = &mut ctx.accounts.recipient_info;
        recipient_info.lockup_seconds = recipient_lockup_seconds;
        
        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>, payment_ids: Vec<u64>) -> Result<()> {
        let recipient = ctx.accounts.recipient.key();
        let recipient_info = &mut ctx.accounts.recipient_info;
        
        // Settle debt first
        settle_debt_internal(recipient_info, ctx.accounts.arbiter_info.as_mut());
        
        let mut total_amount = 0;
        
        // Process each payment
        for i in 0..payment_ids.len() {
            let payment_id = payment_ids[i];
            let payment_account_info = &ctx.remaining_accounts[i];
            
            // Deserialize payment account
            let payment = Account::<Payment>::try_from(payment_account_info)?;
            
            if payment.to != recipient {
                return err!(ErrorCode::CallerNotAllowed);
            }
            
            let current_time = Clock::get()?.unix_timestamp;
            if current_time < payment.release_timestamp {
                return err!(ErrorCode::PaymentIsStillLocked);
            }
            
            if payment.refunded {
                return err!(ErrorCode::PaymentRefunded);
            }
            
            let withdrawal_amount = payment.amount.checked_sub(payment.withdrawn_amount).unwrap();
            total_amount = total_amount.checked_add(withdrawal_amount).unwrap();
            
            // Update payment's withdrawn amount
            let mut payment_mut = Account::<Payment>::try_from_unchecked(payment_account_info)?;
            payment_mut.withdrawn_amount = payment.amount;
            payment_mut.exit(&ctx.program_id)?;
        }
        
        if total_amount > recipient_info.balance {
            return err!(ErrorCode::InsufficientFunds);
        }
        
        // Update recipient balance
        recipient_info.balance = recipient_info.balance.checked_sub(total_amount).unwrap();
        
        // Transfer tokens from protocol vault to recipient
        let seeds = &[
            b"protocol_state".as_ref(),
            &[ctx.accounts.protocol_state.bump],
        ];
        let signer = &[&seeds[..]];
        
        let transfer_cpi_accounts = Transfer {
            from: ctx.accounts.protocol_vault.to_account_info(),
            to: ctx.accounts.recipient_token_account.to_account_info(),
            authority: ctx.accounts.protocol_state.to_account_info(),
        };
        
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new_with_signer(cpi_program, transfer_cpi_accounts, signer);
        token::transfer(cpi_ctx, total_amount)?;
        
        emit!(Withdrawal {
            to: recipient,
            amount: total_amount,
        });
        
        Ok(())
    }

    pub fn update_refund_to(ctx: Context<UpdateRefundTo>, new_refund_to: Pubkey) -> Result<()> {
        if new_refund_to == Pubkey::default() {
            return err!(ErrorCode::RefundToIsZeroAddress);
        }
        
        let payment = &mut ctx.accounts.payment;
        let old_refund_to = payment.refund_to;
        payment.refund_to = new_refund_to;
        
        emit!(RefundToUpdated {
            payment_id: payment.payment_id,
            old_refund_to,
            new_refund_to,
        });
        
        Ok(())
    }

    // Implementation for early withdrawal would be more complex in Solana
    // due to signature verification differences
    pub fn early_withdraw_by_arbiter(
        ctx: Context<EarlyWithdrawByArbiter>,
        payment_ids: Vec<u64>,
        withdrawal_amounts: Vec<u64>,
        fee_amount: u64,
        expiry: i64,
        salt: u64,
    ) -> Result<()> {
        if payment_ids.len() != withdrawal_amounts.len() {
            return err!(ErrorCode::MismatchedEarlyWithdrawalArrays);
        }
        
        let current_time = Clock::get()?.unix_timestamp;
        if current_time > expiry {
            return err!(ErrorCode::WithdrawalHashExpired);
        }
        
        let recipient = ctx.accounts.recipient.key();
        let recipient_info = &mut ctx.accounts.recipient_info;
        let arbiter_info = &mut ctx.accounts.arbiter_info;
        
        let mut total_amount = 0;
        
        // Process each payment
        for i in 0..payment_ids.len() {
            let payment_id = payment_ids[i];
            let withdrawal_amount = withdrawal_amounts[i];
            let payment_account_info = &ctx.remaining_accounts[i];
            
            // Deserialize payment account
            let payment = Account::<Payment>::try_from(payment_account_info)?;
            
            if payment.to != recipient {
                return err!(ErrorCode::PaymentDoesNotBelongToRecipient);
            }
            
            if withdrawal_amount > payment.amount {
                return err!(ErrorCode::InvalidWithdrawalAmount);
            }
            
            if payment.refunded {
                return err!(ErrorCode::PaymentRefunded);
            }
            
            total_amount = total_amount.checked_add(withdrawal_amount).unwrap();
            
            // Update payment's withdrawn amount
            let mut payment_mut = Account::<Payment>::try_from_unchecked(payment_account_info)?;
            payment_mut.withdrawn_amount = payment_mut.withdrawn_amount.checked_add(withdrawal_amount).unwrap();
            payment_mut.exit(&ctx.program_id)?;
        }
        
        if fee_amount > total_amount {
            return err!(ErrorCode::InvalidFeeAmount);
        }
        
        if recipient_info.balance < total_amount {
            return err!(ErrorCode::InsufficientFunds);
        }
        
        // Update recipient balance
        recipient_info.balance = recipient_info.balance.checked_sub(total_amount).unwrap();
        
        // Update arbiter balance with the fee
        arbiter_info.balance = arbiter_info.balance.checked_add(fee_amount).unwrap();
        
        // Transfer tokens from protocol vault to recipient
        let seeds = &[
            b"protocol_state".as_ref(),
            &[ctx.accounts.protocol_state.bump],
        ];
        let signer = &[&seeds[..]];
        
        let transfer_amount = total_amount.checked_sub(fee_amount).unwrap();
        
        let transfer_cpi_accounts = Transfer {
            from: ctx.accounts.protocol_vault.to_account_info(),
            to: ctx.accounts.recipient_token_account.to_account_info(),
            authority: ctx.accounts.protocol_state.to_account_info(),
        };
        
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new_with_signer(cpi_program, transfer_cpi_accounts, signer);
        token::transfer(cpi_ctx, transfer_amount)?;
        
        emit!(Withdrawal {
            to: recipient,
            amount: total_amount,
        });
        
        emit!(WithdrawalFeePaid {
            recipient,
            amount: fee_amount,
        });
        
        Ok(())
    }
}

// Helper function for settling debt
fn settle_debt_internal(recipient_info: &mut Account<RecipientInfo>, arbiter_info: &mut Account<ArbiterInfo>) -> Result<()> {
    let recipient_debt = recipient_info.debt;
    let recipient_balance = recipient_info.balance;
    
    let settle_amount = std::cmp::min(recipient_balance, recipient_debt);
    
    recipient_info.balance = recipient_info.balance.checked_sub(settle_amount).unwrap();
    arbiter_info.balance = arbiter_info.balance.checked_add(settle_amount).unwrap();
    recipient_info.debt = recipient_info.debt.checked_sub(settle_amount).unwrap();
    
    Ok(())
}

// State accounts
#[account]
pub struct ProtocolState {
    pub arbiter: Pubkey,
    pub token_mint: Pubkey,
    pub nonce: u64,
    pub bump: u8,
}

#[account]
pub struct Payment {
    pub to: Pubkey,
    pub amount: u64,
    pub release_timestamp: i64,
    pub refund_to: Pubkey,
    pub withdrawn_amount: u64,
    pub refunded: bool,
    pub payment_id: u64,
    pub bump: u8,
}

#[account]
pub struct RecipientInfo {
    pub recipient: Pubkey,
    pub balance: u64,
    pub debt: u64,
    pub lockup_seconds: i64,
    pub bump: u8,
}

#[account]
pub struct ArbiterInfo {
    pub arbiter: Pubkey,
    pub balance: u64,
    pub bump: u8,
}

// Events
#[event]
pub struct PaymentCreated {
    #[index]
    pub payment_id: u64,
    #[index]
    pub to: Pubkey,
    pub amount: u64,
    pub release_timestamp: i64,
    #[index]
    pub refund_to: Pubkey,
}

#[event]
pub struct Refund {
    #[index]
    pub payment_id: u64,
    #[index]
    pub refund_to: Pubkey,
    pub amount: u64,
}

#[event]
pub struct RefundToUpdated {
    #[index]
    pub payment_id: u64,
    #[index]
    pub old_refund_to: Pubkey,
    #[index]
    pub new_refund_to: Pubkey,
}

#[event]
pub struct Withdrawal {
    #[index]
    pub to: Pubkey,
    pub amount: u64,
}

#[event]
pub struct WithdrawalFeePaid {
    #[index]
    pub recipient: Pubkey,
    pub amount: u64,
}

// Error codes
#[error_code]
pub enum ErrorCode {
    #[msg("Caller not allowed")]
    CallerNotAllowed,
    #[msg("Payment is still locked")]
    PaymentIsStillLocked,
    #[msg("Payment does not belong to recipient")]
    PaymentDoesNotBelongToRecipient,
    #[msg("Refund to address cannot be zero address")]
    RefundToIsZeroAddress,
    #[msg("Insufficient funds")]
    InsufficientFunds,
    #[msg("Invalid withdrawal amount")]
    InvalidWithdrawalAmount,
    #[msg("Invalid fee amount")]
    InvalidFeeAmount,
    #[msg("Invalid signature")]
    InvalidSignature,
    #[msg("Withdrawal hash already used")]
    WithdrawalHashAlreadyUsed,
    #[msg("Withdrawal hash expired")]
    WithdrawalHashExpired,
    #[msg("Payment already refunded")]
    PaymentRefunded,
    #[msg("Lockup seconds exceeds maximum")]
    LockupSecondsExceedsMax,
    #[msg("Mismatched early withdrawal arrays")]
    MismatchedEarlyWithdrawalArrays,
}

// Context structs for instructions
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub initializer: Signer<'info>,
    #[account(
        init,
        payer = initializer,
        space = 8 + std::mem::size_of::<ProtocolState>(),
        seeds = [b"protocol_state"],
        bump
    )]
    pub protocol_state: Account<'info, ProtocolState>,
    pub token_mint: Account<'info, token::Mint>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Pay<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        mut,
        seeds = [b"protocol_state"],
        bump = protocol_state.bump
    )]
    pub protocol_state: Account<'info, ProtocolState>,
    /// CHECK: This is the recipient
    pub recipient: AccountInfo<'info>,
    #[account(
        init_if_needed,
        payer = payer,
        space = 8 + std::mem::size_of::<RecipientInfo>(),
        seeds = [b"recipient_info", recipient.key().as_ref()],
        bump
    )]
    pub recipient_info: Account<'info, RecipientInfo>,
    #[account(
        init,
        payer = payer,
        space = 8 + std::mem::size_of::<Payment>(),
        seeds = [b"payment", protocol_state.nonce.to_le_bytes().as_ref()],
        bump
    )]
    pub payment: Account<'info, Payment>,
    #[account(
        mut,
        constraint = payer_token_account.owner == payer.key(),
        constraint = payer_token_account.mint == protocol_state.token_mint
    )]
    pub payer_token_account: Account<'info, TokenAccount>,
    #[account(
        mut,
        constraint = protocol_vault.owner == protocol_state.key(),
        constraint = protocol_vault.mint == protocol_state.token_mint
    )]
    pub protocol_vault: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RefundByRecipient<'info> {
    #[account(
        mut,
        constraint = recipient.key() == payment.to
    )]
    pub recipient: Signer<'info>,
    #[account(
        mut,
        seeds = [b"protocol_state"],
        bump = protocol_state.bump
    )]
    pub protocol_state: Account<'info, ProtocolState>,
    #[account(
        mut,
        seeds = [b"payment", payment.payment_id.to_le_bytes().as_ref()],
        bump = payment.bump
    )]
    pub payment: Account<'info, Payment>,
    #[account(
        mut,
        seeds = [b"recipient_info", recipient.key().as_ref()],
        bump = recipient_info.bump
    )]
    pub recipient_info: Account<'info, RecipientInfo>,
    #[account(
        mut,
        constraint = protocol_vault.owner == protocol_state.key(),
        constraint = protocol_vault.mint == protocol_state.token_mint
    )]
    pub protocol_vault: Account<'info, TokenAccount>,
    #[account(
        mut,
        constraint = refund_to_token_account.owner == payment.refund_to,
        constraint = refund_to_token_account.mint == protocol_state.token_mint
    )]
    pub refund_to_token_account: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct RefundByArbiter<'info> {
    #[account(
        mut,
        constraint = arbiter.key() == protocol_state.arbiter
    )]
    pub arbiter: Signer<'info>,
    #[account(
        mut,
        seeds = [b"protocol_state"],
        bump = protocol_state.bump
    )]
    pub protocol_state: Account<'info, ProtocolState>,
    #[account(
        mut,
        seeds = [b"payment", payment.payment_id.to_le_bytes().as_ref()],
        bump = payment.bump
    )]
    pub payment: Account<'info, Payment>,
    #[account(
        mut,
        seeds = [b"recipient_info", payment.to.as_ref()],
        bump = recipient_info.bump
    )]
    pub recipient_info: Account<'info, RecipientInfo>,
    #[account(
        init_if_needed,
        payer = arbiter,
        space = 8 + std::mem::size_of::<ArbiterInfo>(),
        seeds = [b"arbiter_info", arbiter.key().as_ref()],
        bump
    )]
    pub arbiter_info: Account<'info, ArbiterInfo>,
    #[account(
        mut,
        constraint = protocol_vault.owner == protocol_state.key(),
        constraint = protocol_vault.mint == protocol_state.token_mint
    )]
    pub protocol_vault: Account<'info, TokenAccount>,
    #[account(
        mut,
        constraint = refund_to_token_account.owner == payment.refund_to,
        constraint = refund_to_token_account.mint == protocol_state.token_mint
    )]
    pub refund_to_token_account: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SettleDebt<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: This is the recipient
    pub recipient: AccountInfo<'info>,
    #[account(
        mut,
        seeds = [b"recipient_info", recipient.key().as_ref()],
        bump = recipient_info.bump
    )]
    pub recipient_info: Account<'info, RecipientInfo>,
    #[account(
        mut,
        seeds = [b"arbiter_info", protocol_state.arbiter.as_ref()],
        bump = arbiter_info.bump
    )]
    pub arbiter_info: Account<'info, ArbiterInfo>,
    #[account(
        seeds = [b"protocol_state"],
        bump = protocol_state.bump
    )]
    pub protocol_state: Account<'info, ProtocolState>,
}

#[derive(Accounts)]
pub struct DepositArbiterFunds<'info> {
    #[account(
        mut,
        constraint = arbiter.key() == protocol_state.arbiter
    )]
    pub arbiter: Signer<'info>,
    #[account(
        mut,
        seeds = [b"protocol_state"],
        bump = protocol_state.bump
    )]
    pub protocol_state: Account<'info, ProtocolState>,
    #[account(
        mut,
        seeds = [b"arbiter_info", arbiter.key().as_ref()],
        bump = arbiter_info.bump
    )]
    pub arbiter_info: Account<'info, ArbiterInfo>,
    #[account(
        mut,
        constraint = arbiter_token_account.owner == arbiter.key(),
        constraint = arbiter_token_account.mint == protocol_state.token_mint
    )]
    pub arbiter_token_account: Account<'info, TokenAccount>,
    #[account(
        mut,
        constraint = protocol_vault.owner == protocol_state.key(),
        constraint = protocol_vault.mint == protocol_state.token_mint
    )]
    pub protocol_vault: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct WithdrawArbiterFunds<'info> {
    #[account(
        mut,
        constraint = arbiter.key() == protocol_state.arbiter
    )]
    pub arbiter: Signer<'info>,
    #[account(
        mut,
        seeds = [b"protocol_state"],
        bump = protocol_state.bump
    )]
    pub protocol_state: Account<'info, ProtocolState>,
    #[account(
        mut,
        seeds = [b"arbiter_info", arbiter.key().as_ref()],
        bump = arbiter_info.bump
    )]
    pub arbiter_info: Account<'info, ArbiterInfo>,
    #[account(
        mut,
        constraint = arbiter_token_account.owner == arbiter.key(),
        constraint = arbiter_token_account.mint == protocol_state.token_mint
    )]
    pub arbiter_token_account: Account<'info, TokenAccount>,
    #[account(
        mut,
        constraint = protocol_vault.owner == protocol_state.key(),
        constraint = protocol_vault.mint == protocol_state.token_mint
    )]
    pub protocol_vault: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct SetLockupSeconds<'info> {
    #[account(
        mut,
        constraint = arbiter.key() == protocol_state.arbiter
    )]
    pub arbiter: Signer<'info>,
    #[account(
        seeds = [b"protocol_state"],
        bump = protocol_state.bump
    )]
    pub protocol_state: Account<'info, ProtocolState>,
    #[account(
        mut,
        seeds = [b"recipient_info", recipient_info.recipient.as_ref()],
        bump = recipient_info.bump
    )]
    pub recipient_info: Account<'info, RecipientInfo>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub recipient: Signer<'info>,
    #[account(
        mut,
        seeds = [b"protocol_state"],
        bump = protocol_state.bump
    )]
    pub protocol_state: Account<'info, ProtocolState>,
    #[account(
        mut,
        seeds = [b"recipient_info", recipient.key().as_ref()],
        bump = recipient_info.bump
    )]
    pub recipient_info: Account<'info, RecipientInfo>,
    #[account(
        mut,
        seeds = [b"arbiter_info", protocol_state.arbiter.as_ref()],
        bump = arbiter_info.bump
    )]
    pub arbiter_info: Account<'info, ArbiterInfo>,
    #[account(
        mut,
        constraint = recipient_token_account.owner == recipient.key(),
        constraint = recipient_token_account.mint == protocol_state.token_mint
    )]
    pub recipient_token_account: Account<'info, TokenAccount>,
    #[account(
        mut,
        constraint = protocol_vault.owner == protocol_state.key(),
        constraint = protocol_vault.mint == protocol_state.token_mint
    )]
    pub protocol_vault: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
    // remaining_accounts will contain Payment accounts
}

#[derive(Accounts)]
pub struct UpdateRefundTo<'info> {
    #[account(
        mut,
        constraint = refund_to.key() == payment.refund_to
    )]
    pub refund_to: Signer<'info>,
    #[account(
        mut,
        seeds = [b"payment", payment.payment_id.to_le_bytes().as_ref()],
        bump = payment.bump
    )]
    pub payment: Account<'info, Payment>,
}

#[derive(Accounts)]
pub struct EarlyWithdrawByArbiter<'info> {
    #[account(
        mut,
        constraint = arbiter.key() == protocol_state.arbiter
    )]
    pub arbiter: Signer<'info>,
    #[account(
        mut,
        seeds = [b"protocol_state"],
        bump = protocol_state.bump
    )]
    pub protocol_state: Account<'info, ProtocolState>,
    #[account(mut)]
    pub recipient: Signer<'info>,
    #[account(
        mut,
        seeds = [b"recipient_info", recipient.key().as_ref()],
        bump = recipient_info.bump
    )]
    pub recipient_info: Account<'info, RecipientInfo>,
    #[account(
        mut,
        seeds = [b"arbiter_info", arbiter.key().as_ref()],
        bump = arbiter_info.bump
    )]
    pub arbiter_info: Account<'info, ArbiterInfo>,
    #[account(
        mut,
        constraint = recipient_token_account.owner == recipient.key(),
        constraint = recipient_token_account.mint == protocol_state.token_mint
    )]
    pub recipient_token_account: Account<'info, TokenAccount>,
    #[account(
        mut,
        constraint = protocol_vault.owner == protocol_state.key(),
        constraint = protocol_vault.mint == protocol_state.token_mint
    )]
    pub protocol_vault: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
    // remaining_accounts will contain Payment accounts
}