//! Refund Protocol Token (RPT) - A transferrable token for the refund protocol

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Mint, MintTo, Transfer, Burn};

declare_id!("RPT6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS"); // Your RPT program ID

#[program]
pub mod refund_protocol_token {
    use super::*;

    pub fn initialize_token(
        ctx: Context<InitializeToken>,
        decimals: u8,
        name: String,
        symbol: String,
        uri: String,
    ) -> Result<()> {
        let token_info = &mut ctx.accounts.token_info;
        token_info.mint = ctx.accounts.mint.key();
        token_info.decimals = decimals;
        token_info.name = name;
        token_info.symbol = symbol;
        token_info.uri = uri;
        token_info.total_supply = 0;
        token_info.authority = ctx.accounts.authority.key();
        token_info.bump = *ctx.bumps.get("token_info").unwrap();
        
        Ok(())
    }

    // Mint tokens (only by authority)
    pub fn mint_tokens(
        ctx: Context<MintTokens>,
        amount: u64,
    ) -> Result<()> {
        let seeds = &[
            b"token_info".as_ref(),
            &[ctx.accounts.token_info.bump],
        ];
        let signer = &[&seeds[..]];

        let cpi_accounts = MintTo {
            mint: ctx.accounts.mint.to_account_info(),
            to: ctx.accounts.to_token_account.to_account_info(),
            authority: ctx.accounts.token_info.to_account_info(),
        };
        
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new_with_signer(cpi_program, cpi_accounts, signer);
        token::mint_to(cpi_ctx, amount)?;

        // Update total supply
        let token_info = &mut ctx.accounts.token_info;
        token_info.total_supply = token_info.total_supply.checked_add(amount).unwrap();

        emit!(TokensMinted {
            to: ctx.accounts.to_token_account.owner,
            amount,
        });

        Ok(())
    }

    // Burn tokens
    pub fn burn_tokens(
        ctx: Context<BurnTokens>,
        amount: u64,
    ) -> Result<()> {
        let cpi_accounts = Burn {
            mint: ctx.accounts.mint.to_account_info(),
            from: ctx.accounts.from_token_account.to_account_info(),
            authority: ctx.accounts.owner.to_account_info(),
        };
        
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
        token::burn(cpi_ctx, amount)?;

        // Update total supply
        let token_info = &mut ctx.accounts.token_info;
        token_info.total_supply = token_info.total_supply.checked_sub(amount).unwrap();

        emit!(TokensBurned {
            from: ctx.accounts.owner.key(),
            amount,
        });

        Ok(())
    }

    // Stake tokens to earn rewards from protocol fees
    pub fn stake_tokens(
        ctx: Context<StakeTokens>,
        amount: u64,
    ) -> Result<()> {
        // Transfer tokens to staking vault
        let cpi_accounts = Transfer {
            from: ctx.accounts.user_token_account.to_account_info(),
            to: ctx.accounts.staking_vault.to_account_info(),
            authority: ctx.accounts.user.to_account_info(),
        };
        
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
        token::transfer(cpi_ctx, amount)?;

        // Update stake info
        let stake_info = &mut ctx.accounts.stake_info;
        stake_info.staked_amount = stake_info.staked_amount.checked_add(amount).unwrap();
        stake_info.last_claim_timestamp = Clock::get()?.unix_timestamp;

        emit!(TokensStaked {
            user: ctx.accounts.user.key(),
            amount,
        });

        Ok(())
    }

    // Unstake tokens
    pub fn unstake_tokens(
        ctx: Context<UnstakeTokens>,
        amount: u64,
    ) -> Result<()> {
        let stake_info = &mut ctx.accounts.stake_info;
        
        if amount > stake_info.staked_amount {
            return err!(ErrorCode::InsufficientStakedTokens);
        }

        // Transfer tokens back to user
        let seeds = &[
            b"token_info".as_ref(),
            &[ctx.accounts.token_info.bump],
        ];
        let signer = &[&seeds[..]];

        let cpi_accounts = Transfer {
            from: ctx.accounts.staking_vault.to_account_info(),
            to: ctx.accounts.user_token_account.to_account_info(),
            authority: ctx.accounts.token_info.to_account_info(),
        };
        
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new_with_signer(cpi_program, cpi_accounts, signer);
        token::transfer(cpi_ctx, amount)?;

        // Update stake info
        stake_info.staked_amount = stake_info.staked_amount.checked_sub(amount).unwrap();

        emit!(TokensUnstaked {
            user: ctx.accounts.user.key(),
            amount,
        });

        Ok(())
    }

    // Claim staking rewards (protocol fees distributed to stakers)
    pub fn claim_rewards(ctx: Context<ClaimRewards>) -> Result<()> {
        let stake_info = &mut ctx.accounts.stake_info;
        let token_info = &ctx.accounts.token_info;
        
        let current_time = Clock::get()?.unix_timestamp;
        let time_staked = current_time - stake_info.last_claim_timestamp;
        
        // Calculate rewards (simplified - 1% APY for demo)
        let reward_rate = 100; // basis points per year
        let seconds_per_year = 365 * 24 * 60 * 60;
        let rewards = (stake_info.staked_amount as u128)
            .checked_mul(reward_rate as u128).unwrap()
            .checked_mul(time_staked as u128).unwrap()
            .checked_div(10000 * seconds_per_year).unwrap() as u64;

        if rewards > 0 {
            // Mint reward tokens
            let seeds = &[
                b"token_info".as_ref(),
                &[token_info.bump],
            ];
            let signer = &[&seeds[..]];

            let cpi_accounts = MintTo {
                mint: ctx.accounts.mint.to_account_info(),
                to: ctx.accounts.user_token_account.to_account_info(),
                authority: ctx.accounts.token_info.to_account_info(),
            };
            
            let cpi_program = ctx.accounts.token_program.to_account_info();
            let cpi_ctx = CpiContext::new_with_signer(cpi_program, cpi_accounts, signer);
            token::mint_to(cpi_ctx, rewards)?;

            emit!(RewardsClaimed {
                user: ctx.accounts.user.key(),
                amount: rewards,
            });
        }

        stake_info.last_claim_timestamp = current_time;
        Ok(())
    }
}

// State accounts
#[account]
pub struct TokenInfo {
    pub mint: Pubkey,
    pub decimals: u8,
    pub name: String,
    pub symbol: String,
    pub uri: String,
    pub total_supply: u64,
    pub authority: Pubkey,
    pub bump: u8,
}

#[account]
pub struct StakeInfo {
    pub user: Pubkey,
    pub staked_amount: u64,
    pub last_claim_timestamp: i64,
    pub bump: u8,
}

// Events
#[event]
pub struct TokensMinted {
    #[index]
    pub to: Pubkey,
    pub amount: u64,
}

#[event]
pub struct TokensBurned {
    #[index]
    pub from: Pubkey,
    pub amount: u64,
}

#[event]
pub struct TokensStaked {
    #[index]
    pub user: Pubkey,
    pub amount: u64,
}

#[event]
pub struct TokensUnstaked {
    #[index]
    pub user: Pubkey,
    pub amount: u64,
}

#[event]
pub struct RewardsClaimed {
    #[index]
    pub user: Pubkey,
    pub amount: u64,
}

// Error codes
#[error_code]
pub enum ErrorCode {
    #[msg("Insufficient staked tokens")]
    InsufficientStakedTokens,
}

// Context structs
#[derive(Accounts)]
pub struct InitializeToken<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(
        init,
        payer = authority,
        space = 8 + std::mem::size_of::<TokenInfo>(),
        seeds = [b"token_info"],
        bump
    )]
    pub token_info: Account<'info, TokenInfo>,
    #[account(
        init,
        payer = authority,
        mint::decimals = 9,
        mint::authority = token_info,
    )]
    pub mint: Account<'info, Mint>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct MintTokens<'info> {
    #[account(
        mut,
        constraint = authority.key() == token_info.authority
    )]
    pub authority: Signer<'info>,
    #[account(
        mut,
        seeds = [b"token_info"],
        bump = token_info.bump
    )]
    pub token_info: Account<'info, TokenInfo>,
    #[account(
        mut,
        constraint = mint.key() == token_info.mint
    )]
    pub mint: Account<'info, Mint>,
    #[account(
        mut,
        constraint = to_token_account.mint == mint.key()
    )]
    pub to_token_account: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct BurnTokens<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,
    #[account(
        mut,
        seeds = [b"token_info"],
        bump = token_info.bump
    )]
    pub token_info: Account<'info, TokenInfo>,
    #[account(
        mut,
        constraint = mint.key() == token_info.mint
    )]
    pub mint: Account<'info, Mint>,
    #[account(
        mut,
        constraint = from_token_account.mint == mint.key(),
        constraint = from_token_account.owner == owner.key()
    )]
    pub from_token_account: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct StakeTokens<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(
        seeds = [b"token_info"],
        bump = token_info.bump
    )]
    pub token_info: Account<'info, TokenInfo>,
    #[account(
        init_if_needed,
        payer = user,
        space = 8 + std::mem::size_of::<StakeInfo>(),
        seeds = [b"stake_info", user.key().as_ref()],
        bump
    )]
    pub stake_info: Account<'info, StakeInfo>,
    #[account(
        mut,
        constraint = user_token_account.owner == user.key(),
        constraint = user_token_account.mint == token_info.mint
    )]
    pub user_token_account: Account<'info, TokenAccount>,
    #[account(
        mut,
        constraint = staking_vault.owner == token_info.key(),
        constraint = staking_vault.mint == token_info.mint
    )]
    pub staking_vault: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UnstakeTokens<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(
        seeds = [b"token_info"],
        bump = token_info.bump
    )]
    pub token_info: Account<'info, TokenInfo>,
    #[account(
        mut,
        seeds = [b"stake_info", user.key().as_ref()],
        bump = stake_info.bump
    )]
    pub stake_info: Account<'info, StakeInfo>,
    #[account(
        mut,
        constraint = user_token_account.owner == user.key(),
        constraint = user_token_account.mint == token_info.mint
    )]
    pub user_token_account: Account<'info, TokenAccount>,
    #[account(
        mut,
        constraint = staking_vault.owner == token_info.key(),
        constraint = staking_vault.mint == token_info.mint
    )]
    pub staking_vault: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct ClaimRewards<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(
        seeds = [b"token_info"],
        bump = token_info.bump
    )]
    pub token_info: Account<'info, TokenInfo>,
    #[account(
        mut,
        seeds = [b"stake_info", user.key().as_ref()],
        bump = stake_info.bump
    )]
    pub stake_info: Account<'info, StakeInfo>,
    #[account(
        mut,
        constraint = mint.key() == token_info.mint
    )]
    pub mint: Account<'info, Mint>,
    #[account(
        mut,
        constraint = user_token_account.owner == user.key(),
        constraint = user_token_account.mint == token_info.mint
    )]
    pub user_token_account: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}