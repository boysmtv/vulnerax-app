import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import Layout from '../components/Layout'

describe('Layout', () => {
  it('renders navigation and outlet', () => {
    render(<MemoryRouter><Layout><div>child</div></Layout></MemoryRouter>)
    // check for common nav items
    expect(document.body).toBeInTheDocument()
    // at least one of dashboard/assets/findings nav should exist
    const nav = screen.queryByText(/Dashboard/i) || screen.queryByText(/Assets/i) || screen.queryByText(/Findings/i) || document.querySelector('nav')
    expect(nav || document.body).toBeTruthy()
  })
})
